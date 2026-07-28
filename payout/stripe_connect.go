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

	"github.com/nauticana/keel/common"
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
// response. Transfers settle to the connected account's Stripe balance;
// they carry no delivery status of their own.
type stripeConnectTransferResp struct {
	ID                 string `json:"id"`
	BalanceTransaction string `json:"balance_transaction"`
	Created            int64  `json:"created"`
}

// stripeConnectPayoutResp is the relevant subset of the connected-account
// POST /v1/payouts response — the leg that actually moves money to the
// user's bank.
type stripeConnectPayoutResp struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	ArrivalDate int64  `json:"arrival_date"`
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

// RequestInstantPayout disburses in two legs, because a Stripe Transfer
// alone only funds the connected account's Stripe balance — it never
// confirms delivery to a bank:
//
//  1. POST /v1/transfers — platform balance → connected-account balance.
//  2. POST /v1/payouts on the connected account (Stripe-Account header)
//     — connected balance → the user's bank. This payout's id + status
//     are what keel reports.
//
// ProviderPayoutID is "{connectedAccountID}:{payoutID}" so GetPayoutStatus
// and payout.* webhooks can address the payout in its account context;
// ProviderFundingID is the first-leg transfer id (tr_…) — persist both,
// because transfer.reversed events reference the funding leg.
//
// IdempotencyKey rides in the Idempotency-Key header of both calls (the
// payout leg suffixes "-po") — Stripe dedupes within a 24h window so
// network-retry of the same key returns the same objects.
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
	form.Set("metadata[user_id]", strconv.FormatInt(in.UserID, 10))
	form.Set("metadata[partner_id]", strconv.FormatInt(in.PartnerID, 10))

	var transfer stripeConnectTransferResp
	if err := p.doForm(ctx, "/v1/transfers", form, in.IdempotencyKey, "", &transfer); err != nil {
		if isStripeInsufficientBalance(err) {
			return nil, ErrInsufficientBalance
		}
		return nil, fmt.Errorf("stripe connect payout transfer: %w", err)
	}

	payoutForm := url.Values{}
	payoutForm.Set("amount", strconv.FormatInt(in.Amount, 10))
	payoutForm.Set("currency", strings.ToLower(in.Currency))
	payoutForm.Set("method", "instant")
	payoutForm.Set("metadata[transfer_id]", transfer.ID)

	var payout stripeConnectPayoutResp
	if err := p.doForm(ctx, "/v1/payouts", payoutForm, in.IdempotencyKey+"-po", in.ProviderAccountID, &payout); err != nil {
		// The transfer leg already funded the connected balance — return
		// its identity WITH the error so the caller can persist it and
		// recover via ResumePayout (payout leg only, can never re-fund),
		// or retry with the SAME key while Stripe's retention holds.
		partial := &InstantPayoutResult{ProviderFundingID: transfer.ID, Status: "pending"}
		if isStripeInsufficientBalance(err) {
			return partial, ErrInsufficientBalance
		}
		if isStripeInstantUnavailable(err) {
			return partial, ErrInstantPayoutUnavailable
		}
		return partial, fmt.Errorf("stripe connect payout leg (transfer %s created): %w", transfer.ID, err)
	}
	var arrival string
	if payout.ArrivalDate > 0 {
		arrival = time.Unix(payout.ArrivalDate, 0).UTC().Format(time.RFC3339)
	}
	return &InstantPayoutResult{
		ProviderPayoutID:  stripePayoutRef(in.ProviderAccountID, payout.ID),
		ProviderFundingID: transfer.ID,
		Status:            mapStripePayoutStatus(payout.Status),
		EstimatedArrival:  arrival,
	}, nil
}

// isStripeInstantUnavailable detects Stripe's instant-ineligibility
// error class so callers get the typed ErrInstantPayoutUnavailable.
func isStripeInstantUnavailable(err error) bool {
	var apiErr *stripeAPIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		return strings.EqualFold(apiErr.Code, "instant_payouts_unsupported") ||
			strings.EqualFold(apiErr.Code, "instant_payouts_limit_exceeded")
	}
	return false
}

// ResumePayout runs ONLY the payout leg for a payout whose funding
// transfer already succeeded — the recovery operation after
// RequestInstantPayout returned a partial result (ProviderFundingID set,
// no ProviderPayoutID). It never touches /v1/transfers, so it cannot
// re-fund the connected account even after Stripe's ~24h idempotency
// retention has expired; it reuses the derived payout-leg key so an
// in-retention retry returns the same payout. The caller supplies the
// ORIGINAL InstantPayoutInput (same key, amount, currency, destination)
// and the persisted funding transfer id.
//
// PayoutResumer is the optional capability interface downstream workers
// type-assert for two-leg recovery.
func (p *StripeConnectProvider) ResumePayout(ctx context.Context, in InstantPayoutInput, fundingID string) (*InstantPayoutResult, error) {
	if in.ProviderAccountID == "" || fundingID == "" {
		return nil, fmt.Errorf("stripe connect resume payout: ProviderAccountID and fundingID required")
	}
	if in.IdempotencyKey == "" {
		return nil, fmt.Errorf("stripe connect resume payout: IdempotencyKey required")
	}
	// Validate the persisted funding transfer against the caller's input
	// before touching that account's balance.
	var transfer struct {
		ID             string `json:"id"`
		Amount         int64  `json:"amount"`
		AmountReversed int64  `json:"amount_reversed"`
		Reversed       bool   `json:"reversed"`
		Currency       string `json:"currency"`
		Destination    string `json:"destination"`
	}
	if err := p.doGet(ctx, "/v1/transfers/"+fundingID, "", &transfer); err != nil {
		return nil, fmt.Errorf("stripe connect resume payout: funding transfer lookup: %w", err)
	}
	if transfer.Destination != in.ProviderAccountID || transfer.Amount != in.Amount ||
		!strings.EqualFold(transfer.Currency, in.Currency) {
		return nil, fmt.Errorf("stripe connect resume payout: funding transfer %s (dest=%s amount=%d %s) does not match input (dest=%s amount=%d %s)",
			fundingID, transfer.Destination, transfer.Amount, transfer.Currency,
			in.ProviderAccountID, in.Amount, in.Currency)
	}
	// Reconcile first — a payout that already exists is returned even if
	// the funding was later reversed (reversal subtracts from the balance;
	// it does not un-create the payout, and the ledger must learn its id).
	if res, found, err := p.findPayoutByTransfer(ctx, in.ProviderAccountID, fundingID); err != nil {
		return nil, err
	} else if found {
		return res, nil
	}
	// Clawed-back funding must not fund a NEW payout from unrelated funds.
	if transfer.Reversed || transfer.AmountReversed != 0 {
		return nil, fmt.Errorf("stripe connect resume payout: funding transfer %s was reversed (%d of %d) — refusing to create a payout", fundingID, transfer.AmountReversed, transfer.Amount)
	}
	payoutForm := url.Values{}
	payoutForm.Set("amount", strconv.FormatInt(in.Amount, 10))
	payoutForm.Set("currency", strings.ToLower(in.Currency))
	payoutForm.Set("method", "instant")
	payoutForm.Set("metadata[transfer_id]", fundingID)

	var payout stripeConnectPayoutResp
	if err := p.doForm(ctx, "/v1/payouts", payoutForm, in.IdempotencyKey+"-po", in.ProviderAccountID, &payout); err != nil {
		partial := &InstantPayoutResult{ProviderFundingID: fundingID, Status: "pending"}
		if isStripeInsufficientBalance(err) {
			return partial, ErrInsufficientBalance
		}
		if isStripeInstantUnavailable(err) {
			return partial, ErrInstantPayoutUnavailable
		}
		return partial, fmt.Errorf("stripe connect resume payout: %w", err)
	}
	return &InstantPayoutResult{
		ProviderPayoutID:  stripePayoutRef(in.ProviderAccountID, payout.ID),
		ProviderFundingID: fundingID,
		Status:            mapStripePayoutStatus(payout.Status),
	}, nil
}

// findPayoutByTransfer pages GET /v1/payouts (cursor: starting_after
// while has_more) looking for metadata transfer_id — a payout older
// than the newest page must still be found, never recreated.
func (p *StripeConnectProvider) findPayoutByTransfer(ctx context.Context, accountID, fundingID string) (*InstantPayoutResult, bool, error) {
	after := ""
	for {
		path := "/v1/payouts?limit=100"
		if after != "" {
			path += "&starting_after=" + after
		}
		var page struct {
			HasMore bool `json:"has_more"`
			Data    []struct {
				ID       string            `json:"id"`
				Status   string            `json:"status"`
				Metadata map[string]string `json:"metadata"`
			} `json:"data"`
		}
		if err := p.doGet(ctx, path, accountID, &page); err != nil {
			return nil, false, fmt.Errorf("stripe connect resume payout: payout lookup: %w", err)
		}
		for _, po := range page.Data {
			if po.Metadata["transfer_id"] == fundingID {
				return &InstantPayoutResult{
					ProviderPayoutID:  stripePayoutRef(accountID, po.ID),
					ProviderFundingID: fundingID,
					Status:            mapStripePayoutStatus(po.Status),
				}, true, nil
			}
		}
		if !page.HasMore || len(page.Data) == 0 {
			return nil, false, nil
		}
		after = page.Data[len(page.Data)-1].ID
	}
}

// stripePayoutRef packs the connected-account context into the payout id
// — Stripe payout objects only exist in their account's context.
func stripePayoutRef(accountID, payoutID string) string {
	return accountID + ":" + payoutID
}

func splitStripePayoutRef(ref string) (accountID, payoutID string, ok bool) {
	i := strings.IndexByte(ref, ':')
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

func mapStripePayoutStatus(s string) string {
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

// GetPayoutStatus fetches the connected-account payout named by a
// "{account}:{payout}" reference (see stripePayoutRef) — the
// reconciliation path when payout.* webhooks are missed. A bare legacy
// transfer id (tr_…) reports "reversed" when the transfer was reversed
// and "pending" otherwise: a transfer object alone can never prove bank
// delivery.
func (p *StripeConnectProvider) GetPayoutStatus(ctx context.Context, providerPayoutID string) (*InstantPayoutResult, error) {
	if providerPayoutID == "" {
		return nil, fmt.Errorf("stripe connect payout status: id required")
	}
	if accountID, payoutID, ok := splitStripePayoutRef(providerPayoutID); ok {
		var resp stripeConnectPayoutResp
		if err := p.doGet(ctx, "/v1/payouts/"+payoutID, accountID, &resp); err != nil {
			return nil, fmt.Errorf("stripe connect payout status: %w", err)
		}
		return &InstantPayoutResult{
			ProviderPayoutID: providerPayoutID,
			Status:           mapStripePayoutStatus(resp.Status),
		}, nil
	}
	var resp struct {
		ID       string `json:"id"`
		Reversed bool   `json:"reversed"`
	}
	if err := p.doGet(ctx, "/v1/transfers/"+providerPayoutID, "", &resp); err != nil {
		return nil, fmt.Errorf("stripe connect payout status: %w", err)
	}
	status := "pending"
	if resp.Reversed {
		status = "reversed"
	}
	return &InstantPayoutResult{ProviderPayoutID: resp.ID, Status: status}, nil
}

// postForm issues a Stripe form-encoded POST and decodes the 2xx body
// into out. Non-2xx responses parse Stripe's error envelope
// ({"error":{"code":"...","message":"..."}}) into a typed
// *stripeAPIError; callers identify error classes via errors.As.
func (p *StripeConnectProvider) postForm(ctx context.Context, path string, form url.Values, out any) error {
	return p.doForm(ctx, path, form, "", "", out)
}

// doForm / doGet share Stripe request plumbing. stripeAccount, when
// non-empty, rides in the Stripe-Account header to act on a connected
// account's behalf (payout leg, payout status).
func (p *StripeConnectProvider) doForm(ctx context.Context, path string, form url.Values, idempotencyKey, stripeAccount string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiBase+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	return p.doStripe(req, path, stripeAccount, out)
}

func (p *StripeConnectProvider) doGet(ctx context.Context, path, stripeAccount string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBase+path, nil)
	if err != nil {
		return err
	}
	return p.doStripe(req, path, stripeAccount, out)
}

func (p *StripeConnectProvider) doStripe(req *http.Request, path, stripeAccount string, out any) error {
	req.SetBasicAuth(p.apiKey, "")
	if stripeAccount != "" {
		req.Header.Set("Stripe-Account", stripeAccount)
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
	ID      string `json:"id"`
	Type    string `json:"type"`
	Account string `json:"account"` // connected-account context on Connect events
	Created int64  `json:"created"`
	Data    struct {
		Object struct {
			ID               string `json:"id"`
			DetailsSubmitted bool   `json:"details_submitted"`
			ChargesEnabled   bool   `json:"charges_enabled"`
			PayoutsEnabled   bool   `json:"payouts_enabled"`
			Amount           int64  `json:"amount"`
			AmountReversed   int64  `json:"amount_reversed"`
		} `json:"object"`
	} `json:"data"`
}

func (p *StripeConnectProvider) VerifyAndParseWebhook(headers map[string][]string, rawBody []byte) (*PayoutWebhookEvent, error) {
	header := firstHeader(headers, "stripe-signature")
	if header == "" {
		return nil, fmt.Errorf("stripe connect: missing Stripe-Signature header")
	}
	ts, sigs, err := parseStripeSignature(header)
	if err != nil {
		return nil, fmt.Errorf("stripe connect: %w", err)
	}
	expected := p.hmacSHA256Hex([]byte(ts), []byte("."), rawBody)
	if expected == "" {
		return nil, fmt.Errorf("stripe connect: webhook secret not configured")
	}
	// Stripe sends one v1 signature per active endpoint secret during
	// secret rotation — accept the delivery when ANY of them matches.
	matched := false
	for _, sig := range sigs {
		if hmac.Equal([]byte(expected), []byte(sig)) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("stripe connect: invalid signature")
	}
	// Reject stale/future timestamps so a captured delivery can't be replayed
	// later — a valid signature alone doesn't bound freshness.
	tsUnix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("stripe connect: bad signature timestamp: %w", err)
	}
	tol := common.Config().StripeWebhookTolerance
	if age := time.Since(time.Unix(tsUnix, 0)); age > tol || age < -tol {
		return nil, fmt.Errorf("stripe connect: webhook timestamp outside tolerance")
	}

	var ev stripeWebhookEvent
	if err := json.Unmarshal(rawBody, &ev); err != nil {
		return nil, fmt.Errorf("stripe connect: parse: %w", err)
	}
	occurred := ""
	if ev.Created > 0 {
		occurred = time.Unix(ev.Created, 0).UTC().Format(time.RFC3339)
	}
	// Bank-delivery lifecycle rides on the connected account's payout.*
	// events (delivered with the connected-account context in `account`);
	// the id is packed as "{account}:{payout}" to match ProviderPayoutID.
	// transfer.reversed is a balance-leg clawback keyed by the FUNDING
	// leg's tr_… id — downstream ledgers correlate it via the persisted
	// ProviderFundingID, not ProviderPayoutID — and can be PARTIAL:
	// amounts are forwarded so sinks reverse only what Stripe reversed.
	// transfer.created/updated carry no new state — Ignored/ACKed.
	switch ev.Type {
	case "payout.paid", "payout.failed", "payout.canceled":
		typ := PayoutEventTransferPaid
		if ev.Type != "payout.paid" {
			typ = PayoutEventTransferFailed
		}
		return &PayoutWebhookEvent{
			Type:               typ,
			ProviderTransferID: stripePayoutRef(ev.Account, ev.Data.Object.ID),
			RawEventID:         ev.ID,
			OccurredAt:         occurred,
			AmountMinor:        ev.Data.Object.Amount,
		}, nil
	case "transfer.reversed":
		return &PayoutWebhookEvent{
			Type:                PayoutEventTransferReversed,
			ProviderTransferID:  ev.Data.Object.ID,
			RawEventID:          ev.ID,
			OccurredAt:          occurred,
			AmountMinor:         ev.Data.Object.Amount,
			AmountReversedMinor: ev.Data.Object.AmountReversed,
		}, nil
	case "transfer.created", "transfer.updated", "payout.created", "payout.updated":
		return &PayoutWebhookEvent{
			Type:               PayoutEventIgnored,
			ProviderTransferID: ev.Data.Object.ID,
			RawEventID:         ev.ID,
		}, nil
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

func parseStripeSignature(header string) (ts string, sigs []string, err error) {
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			sigs = append(sigs, kv[1])
		}
	}
	if ts == "" || len(sigs) == 0 {
		return "", nil, fmt.Errorf("malformed Stripe-Signature header")
	}
	return ts, sigs, nil
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
