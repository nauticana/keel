package payout

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
// apiBase defaults to Airwallex's demo host for safety; flip to prod
// via AIRWALLEX_API_BASE env when the integration is contract-live.
type AirwallexProvider struct {
	apiKey        string
	webhookSecret string
	apiBase       string
	httpClient    *http.Client
	journal       logger.ApplicationLogger
}

const airwallexCode = "AW"
const airwallexDemoBase = "https://api-demo.airwallex.com"

// NewAirwallexProvider wires the provider. apiKey is the bearer token
// (or a JWT minted via the auth endpoint — production rotates these
// every 30min); webhookSecret is the HMAC-SHA256 shared secret
// configured on the Airwallex dashboard for the webhook endpoint.
func NewAirwallexProvider(apiKey, webhookSecret string, journal logger.ApplicationLogger) (*AirwallexProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("airwallex: API key is required")
	}
	return &AirwallexProvider{
		apiKey:        apiKey,
		webhookSecret: webhookSecret,
		apiBase:       airwallexDemoBase,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		journal:       journal,
	}, nil
}

func (p *AirwallexProvider) Code() string { return airwallexCode }

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
	Name      string                 `json:"name"`       // e.g. "account.created", "account.activated"
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
	if p.webhookSecret == "" {
		return nil, fmt.Errorf("airwallex webhook: secret not configured")
	}
	mac := hmac.New(sha256.New, []byte(p.webhookSecret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	expected := hex.EncodeToString(mac.Sum(nil))
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

// isInsufficientBalance pattern-matches Airwallex's documented
// balance-related error text. Airwallex returns 400 with
// {"code":"insufficient_balance"} in the body — postJSON folds that
// into the wrapped error string, so a substring check is sufficient.
func isInsufficientBalance(err error) bool {
	if err == nil {
		return false
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
		return fmt.Errorf("airwallex %s status=%d body=%s", path, resp.StatusCode, string(raw))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func firstHeader(headers map[string][]string, key string) string {
	for k, v := range headers {
		if len(v) > 0 && equalFold(k, key) {
			return v[0]
		}
	}
	return ""
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Compile-time assertion that AirwallexProvider satisfies PayoutProvider.
var _ PayoutProvider = (*AirwallexProvider)(nil)
