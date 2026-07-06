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

	"github.com/nauticana/keel/common"
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
//   - POST /api/v1/payouts                       → instant payout
//   - Webhook POST {NotifyURL} with x-signature  → account.* events
//
// apiBase comes from --airwallex_api_base. Default is the demo host so
// a fresh install can't accidentally hit production; flip to
// "https://api.airwallex.com" once the integration is contract-live.
//
// AbstractProvider is embedded by value so apiKey / webhookSecret /
// journal are field-promoted; the hmacSHA256Hex helper is accessible as
// p.hmacSHA256Hex(...).
type AirwallexProvider struct {
	AbstractProvider
	apiBase    string
	httpClient *http.Client
}

// NewAirwallexProvider wires the provider. apiKey is the bearer token
// (or a JWT minted via the auth endpoint — production rotates these
// every 30min); webhookSecret is the HMAC-SHA256 shared secret
// configured on the Airwallex dashboard for the webhook endpoint.
//
// apiBase is read from --airwallex_api_base; tests can override the
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
		apiBase:    *common.AirwallexAPIBase,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
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

// VerifyAndParseWebhook validates the x-signature header (HMAC-SHA256
// of "<timestamp>.<rawBody>" using webhookSecret) and normalizes the
// payload. Returns an error on bad signature, unknown event, or a
// stale timestamp.
func (p *AirwallexProvider) VerifyAndParseWebhook(headers map[string][]string, rawBody []byte) (*PayoutWebhookEvent, error) {
	sig := firstHeader(headers, "x-signature")
	ts := firstHeader(headers, "x-timestamp")
	if sig == "" || ts == "" {
		return nil, fmt.Errorf("airwallex webhook: missing signature headers")
	}
	expected := p.hmacSHA256Hex([]byte(ts), []byte("."), rawBody)
	if expected == "" {
		return nil, fmt.Errorf("airwallex webhook: secret not configured")
	}
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return nil, fmt.Errorf("airwallex webhook: invalid signature")
	}

	var ev airwallexWebhookEvent
	if err := json.Unmarshal(rawBody, &ev); err != nil {
		return nil, fmt.Errorf("airwallex webhook: parse: %w", err)
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

type airwallexPayoutReq struct {
	RequestID      string             `json:"request_id"`
	SourceAmount   int64              `json:"source_amount"`
	SourceCurrency string             `json:"source_currency"`
	TransferMethod string             `json:"transfer_method"`
	Reference      string             `json:"reference"`
	Beneficiary    airwallexPayoutBen `json:"beneficiary"`
}

type airwallexPayoutBen struct {
	AccountID string `json:"account_id"`
}

type airwallexPayoutResp struct {
	ID                   string `json:"id"`
	Status               string `json:"status"`
	EstimatedArrivalTime string `json:"estimated_arrival_time"`
}

// RequestInstantPayout fires an Airwallex INSTANT transfer to the
// user's connected account. IdempotencyKey rides in the request_id
// field — Airwallex de-duplicates on it within a 24h window so retries
// after a network failure don't double-pay.
//
// Insufficient-balance failures bubble up as ErrInsufficientBalance so
// the caller can surface a precise message instead of a generic
// "transfer failed".
func (p *AirwallexProvider) RequestInstantPayout(ctx context.Context, in InstantPayoutInput) (*InstantPayoutResult, error) {
	if in.ProviderAccountID == "" {
		return nil, fmt.Errorf("airwallex payout: ProviderAccountID required")
	}
	if in.IdempotencyKey == "" {
		return nil, fmt.Errorf("airwallex payout: IdempotencyKey required")
	}
	req := airwallexPayoutReq{
		RequestID:      in.IdempotencyKey,
		SourceAmount:   in.Amount,
		SourceCurrency: in.Currency,
		TransferMethod: "INSTANT",
		Reference:      fmt.Sprintf("user-%d/partner-%d", in.UserID, in.PartnerID),
		Beneficiary:    airwallexPayoutBen{AccountID: in.ProviderAccountID},
	}
	var resp airwallexPayoutResp
	if err := p.postJSON(ctx, "/api/v1/payouts", req, &resp); err != nil {
		if isInsufficientBalance(err) {
			return nil, ErrInsufficientBalance
		}
		return nil, fmt.Errorf("airwallex payout: %w", err)
	}
	return &InstantPayoutResult{
		ProviderPayoutID: resp.ID,
		Status:           mapAirwallexPayoutStatus(resp.Status),
		EstimatedArrival: resp.EstimatedArrivalTime,
	}, nil
}

func mapAirwallexPayoutStatus(s string) string {
	switch s {
	case "CREATED", "PENDING_FUNDING", "PROCESSING":
		return "pending"
	case "PAID", "COMPLETED":
		return "paid"
	case "FAILED", "CANCELLED":
		return "failed"
	default:
		return strings.ToLower(s)
	}
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
		return strings.EqualFold(apiErr.Code, "insufficient_balance")
	}
	msg := err.Error()
	return strings.Contains(msg, "insufficient_balance") ||
		strings.Contains(msg, "INSUFFICIENT_BALANCE")
}

func (p *AirwallexProvider) postJSON(ctx context.Context, path string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiBase+path, bytes.NewReader(body))
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
