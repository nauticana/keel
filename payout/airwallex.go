package payout

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
)

// AirwallexProvider implements PayoutProvider against Airwallex's
// Connected Accounts + Payouts API. KYC + bank routing is collected in
// Airwallex's hosted onboarding page; the application only stores the
// returned account handle (provider_account_id = Airwallex account id).
//
// API surface used:
//   - POST /api/v1/accounts                      → create connected account
//   - POST /api/v1/accounts/{id}/onboarding_link → hosted KYC URL
//   - POST /api/v1/transfers/create              → payout transfer (to a BENEFICIARY id)
//   - GET  /api/v1/transfers/{id}                → reconciliation lookup
//   - Webhook POST {NotifyURL} with x-signature  → account.* / transfer.* events
//
// apiBase comes from airwallex_api_base. Default is the demo host so
// a fresh install can't accidentally hit production; flip to
// "https://api.airwallex.com" once the integration is contract-live.
//
// AbstractProvider is embedded by value so apiKey / webhookSecret /
// journal are field-promoted; the hmacSHA256Hex helper is accessible as
// p.hmacSHA256Hex(...).
type AirwallexProvider struct {
	AbstractProvider
	apiBase        string
	httpClient     *http.Client
	transferMethod string // payout rail: LOCAL (default) or SWIFT
	transferReason string // documented transfer reason code
}

// NewAirwallexProvider wires the provider. apiKey is the bearer token
// (or a JWT minted via the auth endpoint — production rotates these
// every 30min); webhookSecret is the HMAC-SHA256 shared secret
// configured on the Airwallex dashboard for the webhook endpoint.
//
// apiBase is read from airwallex_api_base; tests can override the
// field directly on the returned struct after construction.
func NewAirwallexProvider(apiKey, webhookSecret string, journal logger.ApplicationLogger) (*AirwallexProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("airwallex: API key is required")
	}
	return &AirwallexProvider{
		AbstractProvider: AbstractProvider{
			apiKey:        apiKey,
			webhookSecret: webhookSecret,
			journal:       journal,
		},
		apiBase:        config.Config().AirwallexAPIBase,
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		transferMethod: firstNonEmpty(config.Config().AirwallexXferMethod, airwallexDefaultMethod),
		transferReason: firstNonEmpty(config.Config().AirwallexXferReason, airwallexDefaultReason),
	}, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (p *AirwallexProvider) Code() string { return ProviderCodeAirwallex }

type airwallexCreateAccountReq struct {
	AccountCurrency string         `json:"account_currency"`
	BusinessType    string         `json:"business_type"`
	Country         string         `json:"country_code"`
	Metadata        map[string]any `json:"metadata"`
	PrimaryContact  map[string]any `json:"primary_contact"`
}

type airwallexCreateAccountResp struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type airwallexOnboardingLinkReq struct {
	ReturnURL  string `json:"return_url"`
	RefreshURL string `json:"refresh_url"`
}

type airwallexOnboardingLinkResp struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at"`
}

// StartOnboarding creates the Airwallex connected account and mints
// the hosted-KYC link. Two-call flow:
//  1. POST /api/v1/accounts to create the connected account, capturing
//     the user/partner pair in metadata so the later webhook back-fill
//     knows which (user, partner) the externalAccountID belongs to.
//  2. POST /api/v1/accounts/{id}/onboarding_link with return + refresh
//     URLs to mint a hosted-KYC link the calling application opens.
func (p *AirwallexProvider) StartOnboarding(ctx context.Context, in StartOnboardingInput) (*PayoutOnboardingSession, error) {
	createReq := airwallexCreateAccountReq{
		AccountCurrency: in.Currency,
		BusinessType:    "INDIVIDUAL",
		Country:         in.CountryCode,
		Metadata: map[string]any{
			"user_id":    in.UserID,
			"partner_id": in.PartnerID,
		},
		PrimaryContact: map[string]any{
			"name":            in.AccountHolder,
			"billing_address": in.BillingAddress,
		},
	}
	var createResp airwallexCreateAccountResp
	if err := p.postJSON(ctx, "/api/v1/accounts", createReq, &createResp); err != nil {
		return nil, fmt.Errorf("airwallex create_account: %w", err)
	}

	linkReq := airwallexOnboardingLinkReq{ReturnURL: in.ReturnURL, RefreshURL: in.ReturnURL}
	var linkResp airwallexOnboardingLinkResp
	if err := p.postJSON(ctx, fmt.Sprintf("/api/v1/accounts/%s/onboarding_link", createResp.ID), linkReq, &linkResp); err != nil {
		return nil, fmt.Errorf("airwallex onboarding_link: %w", err)
	}

	return &PayoutOnboardingSession{
		URL:               linkResp.URL,
		ExternalAccountID: createResp.ID,
		ExpiresAt:         linkResp.ExpiresAt,
	}, nil
}

type airwallexWebhookEvent struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"` // e.g. "account.created", "account.activated"
	AccountID string                 `json:"account_id"`
	Data      map[string]interface{} `json:"data"`
}

// VerifyAndParseWebhook validates the x-signature header — HMAC-SHA256
// of the timestamp concatenated directly with the raw body (no
// separator), per Airwallex's spec — rejects stale/future timestamps,
// and normalizes the payload.
func (p *AirwallexProvider) VerifyAndParseWebhook(headers map[string][]string, rawBody []byte) (*PayoutWebhookEvent, error) {
	sig := firstHeader(headers, "x-signature")
	ts := firstHeader(headers, "x-timestamp")
	if sig == "" || ts == "" {
		return nil, fmt.Errorf("airwallex webhook: missing signature headers")
	}
	expected := p.hmacSHA256Hex([]byte(ts), rawBody)
	if expected == "" {
		return nil, fmt.Errorf("airwallex webhook: secret not configured")
	}
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return nil, fmt.Errorf("airwallex webhook: invalid signature")
	}
	// A valid signature alone doesn't bound freshness — reject replays
	// outside the shared webhook timestamp tolerance.
	when, err := parseAirwallexTimestamp(ts)
	if err != nil {
		return nil, fmt.Errorf("airwallex webhook: bad timestamp: %w", err)
	}
	tol := config.Config().StripeWebhookTolerance
	if age := time.Since(when); age > tol || age < -tol {
		return nil, fmt.Errorf("airwallex webhook: timestamp outside tolerance")
	}

	var ev airwallexWebhookEvent
	if err := json.Unmarshal(rawBody, &ev); err != nil {
		return nil, fmt.Errorf("airwallex webhook: parse: %w", err)
	}
	if strings.HasPrefix(ev.Name, "transfer.") || strings.HasPrefix(ev.Name, "payout.") {
		transferID, _ := ev.Data["id"].(string)
		// Funding events (payout.transfer.funding.*) carry their state
		// under data.funding.status — the top-level transfer status can
		// still read PAID while the funding was reversed; mapping from
		// the wrong field would emit a paid/ignored event for a clawback.
		status, _ := ev.Data["status"].(string)
		if strings.Contains(ev.Name, ".funding.") {
			if funding, ok := ev.Data["funding"].(map[string]interface{}); ok {
				if fs, ok := funding["status"].(string); ok {
					status = fs
				}
			}
		}
		return &PayoutWebhookEvent{
			Type:               mapAirwallexTransferEvent(status),
			ProviderTransferID: transferID,
			RawEventID:         ev.ID,
		}, nil
	}
	mapped, ok := mapAirwallexEventName(ev.Name)
	if !ok {
		return nil, fmt.Errorf("airwallex webhook: unhandled event %q", ev.Name)
	}
	return &PayoutWebhookEvent{
		Type:              mapped,
		ExternalAccountID: ev.AccountID,
		Activated:         mapped == PayoutEventAccountActivated,
		RawEventID:        ev.ID,
	}, nil
}

// mapAirwallexTransferEvent maps a transfer/payout webhook's object
// status to the normalized transfer taxonomy. Non-terminal states are
// Ignored so the webhook is ACKed without dispatching.
func mapAirwallexTransferEvent(status string) PayoutWebhookEventType {
	switch mapAirwallexPayoutStatus(status) {
	case "paid":
		return PayoutEventTransferPaid
	case "failed":
		return PayoutEventTransferFailed
	case "returned":
		return PayoutEventTransferReturned
	case "reversed":
		return PayoutEventTransferReversed
	default:
		return PayoutEventIgnored
	}
}

// parseAirwallexTimestamp accepts the x-timestamp header as RFC3339 or
// unix epoch seconds/milliseconds (digit-length disambiguated).
func parseAirwallexTimestamp(ts string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t, nil
	}
	var n int64
	if _, err := fmt.Sscanf(ts, "%d", &n); err != nil {
		return time.Time{}, fmt.Errorf("unparseable %q", ts)
	}
	if len(ts) >= 13 {
		return time.UnixMilli(n), nil
	}
	return time.Unix(n, 0), nil
}

func mapAirwallexEventName(name string) (PayoutWebhookEventType, bool) {
	switch name {
	case "account.created":
		return PayoutEventAccountCreated, true
	case "account.activated":
		return PayoutEventAccountActivated, true
	case "account.updated":
		return PayoutEventAccountUpdated, true
	case "account.rejected":
		return PayoutEventAccountRejected, true
	}
	return "", false
}

// airwallexTransferReq is the documented POST /api/v1/transfers/create
// request. TransferAmount is an ordinary currency amount — a USD 5.99
// payout sends 5.99, never 599; json.Number keeps the exact
// integer-derived decimal string on the wire without float64.
// TransferMethod is a payout rail (LOCAL / SWIFT) — Airwallex has no
// "INSTANT" method. Reason is required by the contract.
type airwallexTransferReq struct {
	RequestID        string      `json:"request_id"`
	TransferAmount   json.Number `json:"transfer_amount"`
	TransferCurrency string      `json:"transfer_currency"`
	SourceCurrency   string      `json:"source_currency"`
	TransferMethod   string      `json:"transfer_method"`
	Reason           string      `json:"reason"`
	Reference        string      `json:"reference"`
	BeneficiaryID    string      `json:"beneficiary_id"`
}

type airwallexTransferResp struct {
	ID                   string `json:"id"`
	Status               string `json:"status"`
	EstimatedArrivalTime string `json:"estimated_arrival_time"`
}

// Airwallex transfer defaults — deployable configuration via the
// airwallex_transfer_method / airwallex_transfer_reason config flags;
// these constants are only the fallback when the catalog rows are absent.
// The reason must be one of Airwallex's documented codes.
const (
	airwallexDefaultMethod = "LOCAL"
	airwallexDefaultReason = "professional_business_services"
)

// RequestInstantPayout creates an Airwallex transfer to the user's
// BENEFICIARY. ProviderAccountID must be a beneficiary id from
// Airwallex's Beneficiary API — a connected-account id from
// StartOnboarding's hosted KYC is NOT a valid transfer destination; the
// application's onboarding completion must store the beneficiary id on
// user_bank_info before payouts can run.
//
// IdempotencyKey rides in the request_id field — Airwallex
// de-duplicates on it within a 24h window so retries after a network
// failure don't double-pay.
//
// Insufficient-balance failures bubble up as ErrInsufficientBalance so
// the caller can surface a precise message instead of a generic
// "transfer failed".
func (p *AirwallexProvider) RequestInstantPayout(ctx context.Context, in InstantPayoutInput) (*InstantPayoutResult, error) {
	if in.ProviderAccountID == "" {
		return nil, fmt.Errorf("airwallex payout: ProviderAccountID required")
	}
	// The funds flow is platform wallet → Beneficiary. A connected-account
	// id (acct_…) from hosted KYC is a different resource and is rejected
	// loudly here — silently sending it would fail at Airwallex with an
	// opaque validation error, or worse, target the wrong resource.
	if strings.HasPrefix(in.ProviderAccountID, "acct_") {
		return nil, fmt.Errorf("airwallex payout: %q is a connected-account id — payouts require a Beneficiary id; complete beneficiary collection and store it on user_bank_info", in.ProviderAccountID)
	}
	if in.IdempotencyKey == "" {
		return nil, fmt.Errorf("airwallex payout: IdempotencyKey required")
	}
	if in.Currency == "" {
		return nil, fmt.Errorf("airwallex payout: Currency required")
	}
	req := airwallexTransferReq{
		RequestID:        in.IdempotencyKey,
		TransferAmount:   json.Number(minorToDecimal(in.Amount, in.Currency)),
		TransferCurrency: strings.ToUpper(in.Currency),
		SourceCurrency:   strings.ToUpper(in.Currency),
		TransferMethod:   p.transferMethod,
		Reason:           p.transferReason,
		Reference:        fmt.Sprintf("user-%d/partner-%d", in.UserID, in.PartnerID),
		BeneficiaryID:    in.ProviderAccountID,
	}
	var resp airwallexTransferResp
	if err := p.postJSON(ctx, "/api/v1/transfers/create", req, &resp); err != nil {
		if isInsufficientBalance(err) {
			return nil, ErrInsufficientBalance
		}
		return nil, fmt.Errorf("airwallex payout: %w", err)
	}
	return &InstantPayoutResult{
		ProviderPayoutID:  resp.ID,
		ProviderFundingID: resp.ID,
		Status:            mapAirwallexPayoutStatus(resp.Status),
		EstimatedArrival:  resp.EstimatedArrivalTime,
	}, nil
}

// mapAirwallexPayoutStatus normalizes Airwallex transfer states. SENT is
// dispatch to the rail, not delivery — pending. Note Airwallex documents
// that a PAID transfer can LATER become FAILED (rail rejection after
// settlement report); sinks must accept a paid → failed transition.
func mapAirwallexPayoutStatus(s string) string {
	switch strings.ToUpper(s) {
	case "NEW", "CREATED", "PENDING_FUNDING", "PROCESSING", "IN_REVIEW", "SCHEDULED", "SENT", "BOOKED":
		return "pending"
	case "PAID", "COMPLETED", "SETTLED":
		return "paid"
	case "FAILED", "CANCELLED", "REJECTED":
		return "failed"
	case "RETURNED":
		return "returned"
	case "REVERSED":
		return "reversed"
	default:
		return strings.ToLower(s)
	}
}

// CreateBeneficiary registers a payout destination from the details the
// application collected with Airwallex's embedded beneficiary component.
// The payload passes through unstored; the returned id is what
// user_bank_info.provider_account_id must hold for payouts.
func (p *AirwallexProvider) CreateBeneficiary(ctx context.Context, beneficiary json.RawMessage) (string, error) {
	if len(beneficiary) == 0 {
		return "", fmt.Errorf("airwallex beneficiary: payload required")
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := p.postJSON(ctx, "/api/v1/beneficiaries/create", json.RawMessage(beneficiary), &resp); err != nil {
		return "", fmt.Errorf("airwallex create beneficiary: %w", err)
	}
	if resp.ID == "" {
		return "", fmt.Errorf("airwallex create beneficiary: no id returned")
	}
	return resp.ID, nil
}

// GetPayoutStatus fetches GET /api/v1/transfers/{id} — the
// reconciliation path when a transfer webhook was missed.
func (p *AirwallexProvider) GetPayoutStatus(ctx context.Context, providerPayoutID string) (*InstantPayoutResult, error) {
	if providerPayoutID == "" {
		return nil, fmt.Errorf("airwallex payout status: transfer id required")
	}
	var resp airwallexTransferResp
	if err := p.getJSON(ctx, "/api/v1/transfers/"+providerPayoutID, &resp); err != nil {
		return nil, fmt.Errorf("airwallex payout status: %w", err)
	}
	return &InstantPayoutResult{
		ProviderPayoutID: resp.ID,
		Status:           mapAirwallexPayoutStatus(resp.Status),
		EstimatedArrival: resp.EstimatedArrivalTime,
	}, nil
}

// airwallexAPIError is the typed error returned by postJSON whenever
// Airwallex responds with a non-2xx status. Code carries Airwallex's
// canonical error code (e.g. "insufficient_balance"), Message carries
// the human-readable message. RawBody is preserved for diagnostics when
// the envelope didn't parse — every Airwallex error response is JSON,
// but a misbehaving proxy or non-JSON 5xx could land here.
//
// Callers identify specific error classes via errors.As:
//
//	var apiErr *airwallexAPIError
//	if errors.As(err, &apiErr) && apiErr.Code == "insufficient_balance" { ... }
type airwallexAPIError struct {
	Path       string
	StatusCode int
	Code       string
	Message    string
	RawBody    string
}

func (e *airwallexAPIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("airwallex %s status=%d code=%s message=%s",
			e.Path, e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("airwallex %s status=%d body=%s",
		e.Path, e.StatusCode, e.RawBody)
}

// isInsufficientBalance checks for Airwallex's documented
// insufficient-balance error class. Prefers the typed
// airwallexAPIError.Code path (set when the envelope parsed); falls
// back to a substring check when the envelope didn't parse so we
// still detect the class on a non-JSON 4xx body.
func isInsufficientBalance(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *airwallexAPIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		// The current Transfers API returns balance_insufficient; older
		// surfaces used insufficient_balance — accept both.
		return strings.EqualFold(apiErr.Code, "balance_insufficient") ||
			strings.EqualFold(apiErr.Code, "insufficient_balance")
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "insufficient_balance") ||
		strings.Contains(msg, "balance_insufficient")
}

func (p *AirwallexProvider) postJSON(ctx context.Context, path string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return p.doJSON(ctx, http.MethodPost, path, bytes.NewReader(body), out)
}

func (p *AirwallexProvider) getJSON(ctx context.Context, path string, out any) error {
	return p.doJSON(ctx, http.MethodGet, path, nil, out)
}

func (p *AirwallexProvider) doJSON(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, p.apiBase+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		apiErr := &airwallexAPIError{
			Path:       path,
			StatusCode: resp.StatusCode,
			RawBody:    string(raw),
		}
		// Airwallex's documented error envelope: {"code":"...","message":"..."}.
		// Parse best-effort; missing fields leave the typed Code/Message
		// empty and callers fall through to the substring path.
		var envelope struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if jerr := json.Unmarshal(raw, &envelope); jerr == nil {
			apiErr.Code = envelope.Code
			apiErr.Message = envelope.Message
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func firstHeader(headers map[string][]string, key string) string {
	for k, v := range headers {
		if len(v) > 0 && strings.EqualFold(k, key) {
			return v[0]
		}
	}
	return ""
}

// Compile-time assertion that AirwallexProvider satisfies PayoutProvider.
var _ PayoutProvider = (*AirwallexProvider)(nil)
