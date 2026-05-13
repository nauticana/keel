package payout

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/logger"
)

// StripeConnectProvider implements PayoutProvider against Stripe
// Connect. Connected accounts are Express type; the application hands
// the user Stripe's hosted-onboarding URL and Stripe posts back via
// account.updated when `details_submitted=true` and `payouts_enabled=true`.
//
// API surface:
//   - POST /v1/accounts        → create Express connected account
//   - POST /v1/account_links   → hosted KYC URL
//   - POST /v1/transfers       → instant payout (method=instant)
//   - Webhook POST with Stripe-Signature: t=...,v1=... → account.* events
//
// AbstractProvider is embedded by value so apiKey / webhookSecret /
// journal are field-promoted. apiBase is hardcoded to api.stripe.com —
// Stripe has no sandbox host, environment is selected via the secret
// key (sk_test_... vs sk_live_...). Tests can override via the field.
type StripeConnectProvider struct {
	AbstractProvider
	apiBase    string
	httpClient *http.Client
}

const stripeConnectAPIBase = "https://api.stripe.com"

func NewStripeConnectProvider(apiKey, webhookSecret string, journal logger.ApplicationLogger) (*StripeConnectProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("stripe connect: API key is required")
	}
	return &StripeConnectProvider{
		AbstractProvider: AbstractProvider{
			apiKey:        apiKey,
			webhookSecret: webhookSecret,
			journal:       journal,
		},
		apiBase:    stripeConnectAPIBase,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (p *StripeConnectProvider) Code() string { return ProviderCodeStripeConnect }

// stripeConnectAccountResp is the relevant subset of POST /v1/accounts
// response.
type stripeConnectAccountResp struct {
	ID string `json:"id"`
}

// stripeConnectLinkResp is the relevant subset of POST /v1/account_links
// response. ExpiresAt is a unix-seconds timestamp per Stripe's spec.
type stripeConnectLinkResp struct {
	URL       string `json:"url"`
	ExpiresAt int64  `json:"expires_at"`
}

// StartOnboarding creates an Express connected account and mints a
// hosted-onboarding link. Two-call flow mirroring Airwallex:
//  1. POST /v1/accounts with type=express, country, default_currency,
//     email, business_type=individual; metadata carries user_id /
//     partner_id so the later account.updated webhook can re-key.
//  2. POST /v1/account_links with type=account_onboarding + the
//     application's return URL; Stripe expires this URL ~5min from
//     creation.
//
// Email is mandatory on Express accounts — Stripe rejects the create
// otherwise; we surface a clear error rather than a generic 400 from
// upstream.
func (p *StripeConnectProvider) StartOnboarding(ctx context.Context, in StartOnboardingInput) (*PayoutOnboardingSession, error) {
	if in.Email == "" {
		return nil, fmt.Errorf("stripe connect: Email required for Express account creation")
	}
	if in.CountryCode == "" {
		return nil, fmt.Errorf("stripe connect: CountryCode required")
	}
	if in.ReturnURL == "" {
		return nil, fmt.Errorf("stripe connect: ReturnURL required for hosted onboarding")
	}

	createForm := url.Values{}
	createForm.Set("type", "express")
	createForm.Set("country", strings.ToUpper(in.CountryCode))
	createForm.Set("email", in.Email)
	createForm.Set("business_type", "individual")
	if in.Currency != "" {
		createForm.Set("default_currency", strings.ToLower(in.Currency))
	}
	createForm.Set("metadata[user_id]", strconv.FormatInt(in.UserID, 10))
	createForm.Set("metadata[partner_id]", strconv.FormatInt(in.PartnerID, 10))

	var acct stripeConnectAccountResp
	if err := p.postForm(ctx, "/v1/accounts", createForm, &acct); err != nil {
		return nil, fmt.Errorf("stripe connect create account: %w", err)
	}

	linkForm := url.Values{}
	linkForm.Set("account", acct.ID)
	linkForm.Set("refresh_url", in.ReturnURL)
	linkForm.Set("return_url", in.ReturnURL)
	linkForm.Set("type", "account_onboarding")

	var link stripeConnectLinkResp
	if err := p.postForm(ctx, "/v1/account_links", linkForm, &link); err != nil {
		return nil, fmt.Errorf("stripe connect account_links: %w", err)
	}

	// ExpiresAt is unix-seconds; surface it as RFC3339 so the wire shape
	// matches the rest of the providers (Airwallex / Wise return strings).
	var expiresAt string
	if link.ExpiresAt > 0 {
		expiresAt = time.Unix(link.ExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	return &PayoutOnboardingSession{
		URL:               link.URL,
		ExternalAccountID: acct.ID,
		ExpiresAt:         expiresAt,
	}, nil
}

// stripeConnectTransferResp is the relevant subset of POST /v1/transfers
// response.
type stripeConnectTransferResp struct {
	ID                   string `json:"id"`
	BalanceTransaction   string `json:"balance_transaction"`
	Created              int64  `json:"created"`
	Status               string `json:"status"`
	EstimatedArrivalTime int64  `json:"estimated_arrival_date"`
}

// stripeAPIError is the typed error returned by postForm when Stripe
// responds non-2xx. Mirrors airwallexAPIError's shape so error handling
// in OnboardingService is uniform across providers.
type stripeAPIError struct {
	Path       string
	StatusCode int
	Code       string
	Message    string
	RawBody    string
}

func (e *stripeAPIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("stripe %s status=%d code=%s message=%s",
			e.Path, e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("stripe %s status=%d body=%s",
		e.Path, e.StatusCode, e.RawBody)
}

// RequestInstantPayout creates a /v1/transfers row from the platform
// balance to the user's connected-account balance. method="instant"
// requests instant transfer where supported (US/EU only at present);
// Stripe falls back to a standard transfer if instant isn't available.
//
// IdempotencyKey rides in the Idempotency-Key header — Stripe dedupes
// on it within a 24h window so network-retry of the same key returns
// the same transfer id rather than creating a second one.
//
// Insufficient-balance failures bubble up as ErrInsufficientBalance
// (Stripe's code is "balance_insufficient" — checked on the typed error).
func (p *StripeConnectProvider) RequestInstantPayout(ctx context.Context, in InstantPayoutInput) (*InstantPayoutResult, error) {
	if in.ProviderAccountID == "" {
		return nil, fmt.Errorf("stripe connect payout: ProviderAccountID required")
	}
	if in.IdempotencyKey == "" {
		return nil, fmt.Errorf("stripe connect payout: IdempotencyKey required")
	}
	if in.Currency == "" {
		return nil, fmt.Errorf("stripe connect payout: Currency required")
	}

	form := url.Values{}
	form.Set("amount", strconv.FormatInt(in.Amount, 10))
	form.Set("currency", strings.ToLower(in.Currency))
	form.Set("destination", in.ProviderAccountID)
	form.Set("method", "instant")
	form.Set("metadata[user_id]", strconv.FormatInt(in.UserID, 10))
	form.Set("metadata[partner_id]", strconv.FormatInt(in.PartnerID, 10))

	var resp stripeConnectTransferResp
	if err := p.postFormWithIdempotency(ctx, "/v1/transfers", form, in.IdempotencyKey, &resp); err != nil {
		if isStripeInsufficientBalance(err) {
			return nil, ErrInsufficientBalance
		}
		return nil, fmt.Errorf("stripe connect payout: %w", err)
	}
	var arrival string
	if resp.EstimatedArrivalTime > 0 {
		arrival = time.Unix(resp.EstimatedArrivalTime, 0).UTC().Format(time.RFC3339)
	}
	return &InstantPayoutResult{
		ProviderPayoutID: resp.ID,
		Status:           mapStripeTransferStatus(resp.Status),
		EstimatedArrival: arrival,
	}, nil
}

func mapStripeTransferStatus(s string) string {
	switch strings.ToLower(s) {
	case "pending", "in_transit":
		return "pending"
	case "paid":
		return "paid"
	case "failed", "canceled":
		return "failed"
	default:
		return strings.ToLower(s)
	}
}

func isStripeInsufficientBalance(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *stripeAPIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		return strings.EqualFold(apiErr.Code, "balance_insufficient")
	}
	msg := err.Error()
	return strings.Contains(msg, "balance_insufficient") ||
		strings.Contains(msg, "insufficient")
}

// postForm issues a Stripe form-encoded POST and decodes the 2xx body
// into out. Non-2xx responses parse Stripe's error envelope
// ({"error":{"code":"...","message":"..."}}) into a typed
// *stripeAPIError; callers identify error classes via errors.As.
func (p *StripeConnectProvider) postForm(ctx context.Context, path string, form url.Values, out any) error {
	return p.postFormWithIdempotency(ctx, path, form, "", out)
}

func (p *StripeConnectProvider) postFormWithIdempotency(ctx context.Context, path string, form url.Values, idempotencyKey string, out any) error {
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiBase+path, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(p.apiKey, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	const maxRespBytes = 1 << 20 // 1 MiB cap on response body
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		return fmt.Errorf("stripe %s read: %w", path, err)
	}
	if resp.StatusCode >= 300 {
		apiErr := &stripeAPIError{
			Path:       path,
			StatusCode: resp.StatusCode,
			RawBody:    string(raw),
		}
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &envelope) == nil {
			apiErr.Code = envelope.Error.Code
			apiErr.Message = envelope.Error.Message
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

type stripeWebhookEvent struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data struct {
		Object struct {
			ID               string `json:"id"`
			DetailsSubmitted bool   `json:"details_submitted"`
			ChargesEnabled   bool   `json:"charges_enabled"`
			PayoutsEnabled   bool   `json:"payouts_enabled"`
		} `json:"object"`
	} `json:"data"`
}

func (p *StripeConnectProvider) VerifyAndParseWebhook(headers map[string][]string, rawBody []byte) (*PayoutWebhookEvent, error) {
	header := firstHeader(headers, "stripe-signature")
	if header == "" {
		return nil, fmt.Errorf("stripe connect: missing Stripe-Signature header")
	}
	ts, sig, err := parseStripeSignature(header)
	if err != nil {
		return nil, fmt.Errorf("stripe connect: %w", err)
	}
	expected := p.hmacSHA256Hex([]byte(ts), []byte("."), rawBody)
	if expected == "" {
		return nil, fmt.Errorf("stripe connect: webhook secret not configured")
	}
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return nil, fmt.Errorf("stripe connect: invalid signature")
	}

	var ev stripeWebhookEvent
	if err := json.Unmarshal(rawBody, &ev); err != nil {
		return nil, fmt.Errorf("stripe connect: parse: %w", err)
	}
	mapped, ok := mapStripeEvent(ev.Type, ev.Data.Object.DetailsSubmitted && ev.Data.Object.PayoutsEnabled)
	if !ok {
		return nil, fmt.Errorf("stripe connect: unhandled event %q", ev.Type)
	}
	return &PayoutWebhookEvent{
		Type:              mapped,
		ExternalAccountID: ev.Data.Object.ID,
		Activated:         ev.Data.Object.DetailsSubmitted && ev.Data.Object.PayoutsEnabled,
		RawEventID:        ev.ID,
	}, nil
}

func parseStripeSignature(header string) (ts, sig string, err error) {
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			sig = kv[1]
		}
	}
	if ts == "" || sig == "" {
		return "", "", fmt.Errorf("malformed Stripe-Signature header")
	}
	return ts, sig, nil
}

func mapStripeEvent(name string, fullyActivated bool) (PayoutWebhookEventType, bool) {
	switch name {
	case "account.created":
		return PayoutEventAccountCreated, true
	case "account.updated":
		if fullyActivated {
			return PayoutEventAccountActivated, true
		}
		return PayoutEventAccountUpdated, true
	case "account.application.deauthorized":
		return PayoutEventAccountRejected, true
	}
	return "", false
}

var _ PayoutProvider = (*StripeConnectProvider)(nil)
