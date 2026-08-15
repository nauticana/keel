package payout

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
)

// WiseProvider implements PayoutProvider against Wise Platform. Wise
// (formerly TransferWise) uses recipient accounts rather than connected
// accounts; there is NO hosted KYC flow for platform-paid recipients.
// Instead, the recipient is created via API with the platform's
// recipient details. To stay within keel's user_bank_info schema
// (which does NOT carry IBAN/sort_code/etc.), this implementation uses
// Wise's `type=email` recipient — Wise sends the recipient an email
// claim link and they enter their own bank details on Wise's side.
//
// API surface:
//   - POST /v1/accounts                  → create email recipient
//   - POST /v1/quotes                    → quote for outbound transfer
//   - POST /v1/transfers                 → execute transfer
//   - Webhook POST with X-Signature-SHA256 → recipients#* events
//
// Wise signs webhook bodies with RSA-SHA256: X-Signature-SHA256 carries
// a Base64 signature over the raw body, verified with Wise's published
// PUBLIC key — not a shared secret, so AbstractProvider's hmacSHA256Hex
// helper is not used here. The webhookSecret constructor argument holds
// that public key (PEM), not a secret.
//
// apiBase comes from wise_api_base (default sandbox host).
// profileID comes from wise_profile_id (required at boot).
type WiseProvider struct {
	AbstractProvider
	apiBase    string
	profileID  string // string form for URL paths
	profileNum int64  // numeric form — Wise defines profile as int64 on the wire
	httpClient *http.Client
}

func NewWiseProvider(apiKey, webhookSecret string, journal logger.ApplicationLogger) (*WiseProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("wise: API key is required")
	}
	profileID := config.Config().WiseProfileID
	var profileNum int64
	if profileID != "" {
		n, err := strconv.ParseInt(profileID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("wise: wise_profile_id %q is not numeric — Wise defines the profile id as an integer", profileID)
		}
		profileNum = n
	}
	return &WiseProvider{
		AbstractProvider: AbstractProvider{
			apiKey:        apiKey,
			webhookSecret: webhookSecret,
			journal:       journal,
		},
		apiBase:    config.Config().WiseAPIBase,
		profileID:  profileID,
		profileNum: profileNum,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (p *WiseProvider) Code() string { return ProviderCodeWise }

// wiseRecipientReq is the POST /v1/accounts request body for an
// email-type recipient. Wise expects camelCase JSON fields and defines
// profile as an int64 — serializing it as a string fails validation.
type wiseRecipientReq struct {
	Currency          string         `json:"currency"`
	Type              string         `json:"type"`
	Profile           int64          `json:"profile"`
	AccountHolderName string         `json:"accountHolderName"`
	Details           map[string]any `json:"details"`
}

type wiseRecipientResp struct {
	ID int64 `json:"id"`
}

// StartOnboarding creates a Wise email-type recipient. There's no
// hosted KYC URL to return — Wise emails the recipient a claim link
// directly and they confirm asynchronously, at which point the
// recipients#state-change webhook (schema 4.0) fires with
// current_state="active" (legacy recipients#updated status="ACTIVE" is
// still mapped). URL stays empty so sail's frontend treats this as
// "linked, awaiting claim".
//
// Required input fields:
//   - Email          — the recipient's claim address
//   - AccountHolder  — display name
//   - Currency       — Wise rejects mismatch between recipient currency
//     and later transfer currency
func (p *WiseProvider) StartOnboarding(ctx context.Context, in StartOnboardingInput) (*PayoutOnboardingSession, error) {
	if p.profileID == "" {
		return nil, fmt.Errorf("wise: wise_profile_id required")
	}
	if in.Email == "" {
		return nil, fmt.Errorf("wise: Email required for email-type recipient")
	}
	if in.AccountHolder == "" {
		return nil, fmt.Errorf("wise: AccountHolder required")
	}
	if in.Currency == "" {
		return nil, fmt.Errorf("wise: Currency required")
	}
	// Email recipients require prior enablement on the Wise profile and
	// are NOT available in sandbox — fail loudly instead of creating a
	// recipient that can never activate.
	if strings.Contains(p.apiBase, "sandbox") {
		return nil, fmt.Errorf("wise: email-type recipients are not available in the Wise sandbox — onboarding requires the production API with the capability enabled on the profile")
	}

	req := wiseRecipientReq{
		Currency:          strings.ToUpper(in.Currency),
		Type:              "email",
		Profile:           p.profileNum,
		AccountHolderName: in.AccountHolder,
		Details: map[string]any{
			"email": in.Email,
		},
	}
	var resp wiseRecipientResp
	if err := p.postJSON(ctx, "/v1/accounts", req, &resp); err != nil {
		return nil, fmt.Errorf("wise create recipient: %w", err)
	}
	return &PayoutOnboardingSession{
		URL:               "", // no hosted flow
		ExternalAccountID: fmt.Sprintf("%d", resp.ID),
		ExpiresAt:         "",
	}, nil
}

// wiseQuoteReq amounts are ordinary source-currency decimals — a USD
// 5.99 payout sends 5.99, never 599. json.Number keeps the exact
// integer-derived decimal string on the wire without float64.
type wiseQuoteReq struct {
	SourceCurrency string       `json:"sourceCurrency"`
	TargetCurrency string       `json:"targetCurrency"`
	SourceAmount   *json.Number `json:"sourceAmount,omitempty"`
	TargetAmount   *json.Number `json:"targetAmount,omitempty"`
}

type wiseQuoteResp struct {
	ID string `json:"id"` // quote UUID
}

type wiseTransferReq struct {
	TargetAccount         int64          `json:"targetAccount"`
	Quote                 string         `json:"quote"`
	CustomerTransactionID string         `json:"customerTransactionId"` // idempotency key
	Details               map[string]any `json:"details,omitempty"`
}

type wiseTransferResp struct {
	ID                int64  `json:"id"`
	Status            string `json:"status"`
	EstimatedDelivery string `json:"estimatedDelivery"`
}

// RequestInstantPayout creates a Wise quote + transfer, then funds the
// transfer from the platform's Wise balance
// (POST /v3/profiles/{profile}/transfers/{id}/payments, type=BALANCE).
// Without the funding call the transfer would sit in
// incoming_payment_waiting forever — creation alone is NOT disbursement.
//
// Amounts on the quote are ordinary source-currency decimals; the
// integer minor-unit input converts via minorToDecimal (599 USD → 5.99).
//
// IdempotencyKey rides in customerTransactionId per Wise's spec; Wise
// dedupes transfer creation on it within the platform profile. A
// funding failure after creation returns an error with the same key
// still valid — a retry re-creates nothing and re-attempts funding.
//
// SCA note: profiles with Strong Customer Authentication enabled reject
// the balance payment with an approval challenge; that surfaces as the
// funding error below and must be resolved at the profile level.
func (p *WiseProvider) RequestInstantPayout(ctx context.Context, in InstantPayoutInput) (*InstantPayoutResult, error) {
	if p.profileID == "" {
		return nil, fmt.Errorf("wise payout: wise_profile_id required")
	}
	if in.ProviderAccountID == "" {
		return nil, fmt.Errorf("wise payout: ProviderAccountID required")
	}
	if in.IdempotencyKey == "" {
		return nil, fmt.Errorf("wise payout: IdempotencyKey required")
	}
	if in.Currency == "" {
		return nil, fmt.Errorf("wise payout: Currency required")
	}

	// Quote first — Wise rejects /v1/transfers without a quote uuid.
	srcAmt := json.Number(minorToDecimal(in.Amount, in.Currency))
	quote := wiseQuoteReq{
		SourceCurrency: strings.ToUpper(in.Currency),
		TargetCurrency: strings.ToUpper(in.Currency),
		SourceAmount:   &srcAmt,
	}
	var qResp wiseQuoteResp
	if err := p.postJSON(ctx, fmt.Sprintf("/v3/profiles/%s/quotes", p.profileID), quote, &qResp); err != nil {
		if isWiseInsufficientBalance(err) {
			return nil, ErrInsufficientBalance
		}
		return nil, fmt.Errorf("wise payout quote: %w", err)
	}

	// targetAccount expects an int64 — provider_account_id was stored
	// as the string form of the recipient id; parse it back.
	var recipientID int64
	if _, err := fmt.Sscanf(in.ProviderAccountID, "%d", &recipientID); err != nil {
		return nil, fmt.Errorf("wise payout: invalid recipient id %q: %w", in.ProviderAccountID, err)
	}

	transfer := wiseTransferReq{
		TargetAccount:         recipientID,
		Quote:                 qResp.ID,
		CustomerTransactionID: wiseIdempotencyUUID(in.IdempotencyKey),
	}
	var tResp wiseTransferResp
	if err := p.postJSON(ctx, "/v1/transfers", transfer, &tResp); err != nil {
		if isWiseInsufficientBalance(err) {
			return nil, ErrInsufficientBalance
		}
		return nil, fmt.Errorf("wise payout transfer: %w", err)
	}

	transferID := fmt.Sprintf("%d", tResp.ID)
	// The transfer now exists — every failure below returns its identity
	// alongside the error so the caller can persist it, retry with the
	// SAME idempotency key, or reconcile via GetPayoutStatus.
	partial := &InstantPayoutResult{
		ProviderPayoutID:  transferID,
		ProviderFundingID: transferID,
		Status:            "pending",
	}
	fund, err := p.fundTransfer(ctx, transferID)
	if err != nil {
		if isWiseInsufficientBalance(err) {
			return partial, ErrInsufficientBalance
		}
		return partial, fmt.Errorf("wise payout fund transfer %s: %w", transferID, err)
	}
	if strings.EqualFold(fund.Status, "REJECTED") {
		// Wise reports funding rejection on an HTTP 200 with a typed
		// errorCode — map the documented insufficient-funds class.
		if strings.EqualFold(fund.ErrorCode, "transfer.insufficient_funds") ||
			strings.Contains(strings.ToLower(fund.ErrorCode), "insufficient") {
			return partial, ErrInsufficientBalance
		}
		return partial, fmt.Errorf("wise payout fund transfer %s: funding rejected (%s)", transferID, fund.ErrorCode)
	}
	return &InstantPayoutResult{
		ProviderPayoutID:  transferID,
		ProviderFundingID: transferID,
		Status:            mapWiseTransferStatus(tResp.Status),
		EstimatedArrival:  tResp.EstimatedDelivery,
	}, nil
}

type wiseFundReq struct {
	Type string `json:"type"`
}

type wiseFundResp struct {
	Status    string `json:"status"`    // COMPLETED / REJECTED
	ErrorCode string `json:"errorCode"` // e.g. transfer.insufficient_funds on REJECTED
}

// fundTransfer pays a created transfer from the profile's Wise balance.
func (p *WiseProvider) fundTransfer(ctx context.Context, transferID string) (*wiseFundResp, error) {
	var resp wiseFundResp
	err := p.postJSON(ctx,
		fmt.Sprintf("/v3/profiles/%s/transfers/%s/payments", p.profileID, transferID),
		wiseFundReq{Type: "BALANCE"}, &resp)
	return &resp, err
}

// GetPayoutStatus fetches GET /v1/transfers/{id} — the reconciliation
// path when the transfers#state-change webhook was missed.
func (p *WiseProvider) GetPayoutStatus(ctx context.Context, providerPayoutID string) (*InstantPayoutResult, error) {
	if providerPayoutID == "" {
		return nil, fmt.Errorf("wise payout status: transfer id required")
	}
	var resp wiseTransferResp
	if err := p.getJSON(ctx, "/v1/transfers/"+providerPayoutID, &resp); err != nil {
		return nil, fmt.Errorf("wise payout status: %w", err)
	}
	return &InstantPayoutResult{
		ProviderPayoutID: providerPayoutID,
		Status:           mapWiseTransferStatus(resp.Status),
		EstimatedArrival: resp.EstimatedDelivery,
	}, nil
}

// mapWiseTransferStatus normalizes Wise transfer states. bounced_back is
// deliberately NON-terminal: Wise documents it may resume processing and
// still deliver, or later progress to funds_refunded — treating it as
// returned would prematurely reverse a legitimate payout.
func mapWiseTransferStatus(s string) string {
	switch strings.ToLower(s) {
	case "incoming_payment_waiting", "processing", "funds_converted",
		"waiting_recipient_input_to_proceed", "bounced_back":
		return "pending"
	case "outgoing_payment_sent":
		return "paid"
	case "cancelled":
		return "failed"
	case "funds_refunded":
		return "returned"
	case "charged_back":
		return "reversed"
	default:
		return strings.ToLower(s)
	}
}

// wiseAPIError is the typed error for non-2xx Wise responses. Wise's
// error envelope is { "errors": [{"code":"...","message":"..."}, ...] }
// — we surface the first entry plus the raw body for diagnostics.
type wiseAPIError struct {
	Path       string
	StatusCode int
	Code       string
	Message    string
	RawBody    string
}

func (e *wiseAPIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("wise %s status=%d code=%s message=%s",
			e.Path, e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("wise %s status=%d body=%s",
		e.Path, e.StatusCode, e.RawBody)
}

func isWiseInsufficientBalance(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *wiseAPIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		// Wise uses various codes for funding shortfalls; cover the
		// documented ones plus a substring fallback.
		if strings.EqualFold(apiErr.Code, "balance.insufficient_funds") ||
			strings.EqualFold(apiErr.Code, "insufficient_funds") ||
			strings.EqualFold(apiErr.Code, "INSUFFICIENT_FUNDS") {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "insufficient_funds") ||
		strings.Contains(msg, "insufficient funds")
}

func (p *WiseProvider) postJSON(ctx context.Context, path string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return p.doJSON(ctx, http.MethodPost, path, bytes.NewReader(body), out)
}

func (p *WiseProvider) getJSON(ctx context.Context, path string, out any) error {
	return p.doJSON(ctx, http.MethodGet, path, nil, out)
}

func (p *WiseProvider) doJSON(ctx context.Context, method, path string, body io.Reader, out any) error {
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
	const maxRespBytes = 1 << 20 // 1 MiB cap
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if err != nil {
		return fmt.Errorf("wise %s read: %w", path, err)
	}
	if resp.StatusCode >= 300 {
		apiErr := &wiseAPIError{
			Path:       path,
			StatusCode: resp.StatusCode,
			RawBody:    string(raw),
		}
		var envelope struct {
			Errors []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		if json.Unmarshal(raw, &envelope) == nil && len(envelope.Errors) > 0 {
			apiErr.Code = envelope.Errors[0].Code
			apiErr.Message = envelope.Errors[0].Message
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// wiseResourceID tolerates both JSON string and numeric forms — Wise
// sends numeric ids for transfers and either form for recipients.
type wiseResourceID string

func (w *wiseResourceID) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*w = wiseResourceID(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*w = wiseResourceID(n.String())
	return nil
}

type wiseWebhookEvent struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	SentAt    string `json:"sent_at"`
	Data      struct {
		Resource struct {
			ID         wiseResourceID `json:"id"`
			Type       string         `json:"type"`
			Status     string         `json:"status"`
			OccurredAt string         `json:"occurred_at"`
			// recipients#state-change (schema 4.0) nests id + action here.
			Data struct {
				RecipientID wiseResourceID `json:"recipientId"`
				State       string         `json:"state"`
			} `json:"data"`
		} `json:"resource"`
		CurrentState string `json:"current_state"` // transfers#state-change
		OccurredAt   string `json:"occurred_at"`
	} `json:"data"`
}

// wisePublicKey parses the PEM-encoded RSA public key held in
// webhookSecret (PKIX "PUBLIC KEY" or PKCS#1 "RSA PUBLIC KEY" blocks).
func (p *WiseProvider) wisePublicKey() (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(p.webhookSecret))
	if block == nil {
		return nil, fmt.Errorf("wise: webhook public key is not PEM")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if pub, ok := key.(*rsa.PublicKey); ok {
			return pub, nil
		}
		return nil, fmt.Errorf("wise: webhook public key is not RSA")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func (p *WiseProvider) VerifyAndParseWebhook(headers map[string][]string, rawBody []byte) (*PayoutWebhookEvent, error) {
	sigB64 := firstHeader(headers, "x-signature-sha256")
	if sigB64 == "" {
		return nil, fmt.Errorf("wise: missing X-Signature-SHA256 header")
	}
	if p.webhookSecret == "" {
		return nil, fmt.Errorf("wise: webhook public key not configured")
	}
	pub, err := p.wisePublicKey()
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("wise: signature is not base64: %w", err)
	}
	digest := sha256.Sum256(rawBody)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("wise: invalid signature")
	}

	var ev wiseWebhookEvent
	if err := json.Unmarshal(rawBody, &ev); err != nil {
		return nil, fmt.Errorf("wise: parse: %w", err)
	}
	occurred := ev.Data.OccurredAt
	if occurred == "" {
		occurred = ev.SentAt
	}
	if ev.EventType == "transfers#state-change" {
		// The state-change payload carries no event_id — synthesize a
		// deterministic one so redeliveries still dedupe durably.
		eventID := ev.EventID
		if eventID == "" {
			eventID = fmt.Sprintf("transfer:%s:%s:%s", ev.Data.Resource.ID, ev.Data.CurrentState, occurred)
		}
		return &PayoutWebhookEvent{
			Type:               mapWiseTransferEvent(ev.Data.CurrentState),
			ProviderTransferID: string(ev.Data.Resource.ID),
			RawEventID:         eventID,
			OccurredAt:         occurred,
		}, nil
	}
	if ev.EventType == "recipients#state-change" {
		// Schema 4.0: action at data.resource.data.state (CREATE/UPDATE/
		// DELETE), timestamp at data.resource.occurred_at. The event has
		// no activation flag — OnboardingService reconciles via
		// IsAccountActive before activating.
		recipientID := string(ev.Data.Resource.Data.RecipientID)
		if recipientID == "" {
			recipientID = string(ev.Data.Resource.ID)
		}
		if ev.Data.Resource.OccurredAt != "" {
			occurred = ev.Data.Resource.OccurredAt
		}
		state := strings.ToUpper(ev.Data.Resource.Data.State)
		eventID := ev.EventID
		if eventID == "" {
			eventID = fmt.Sprintf("recipient:%s:%s:%s", recipientID, state, occurred)
		}
		typ := PayoutEventAccountUpdated
		switch state {
		case "CREATE":
			typ = PayoutEventAccountCreated
		case "DELETE", "DEACTIVATE", "BLOCK":
			typ = PayoutEventAccountRejected
		}
		return &PayoutWebhookEvent{
			Type:              typ,
			ExternalAccountID: recipientID,
			RawEventID:        eventID,
			OccurredAt:        occurred,
		}, nil
	}
	mapped, ok := mapWiseEvent(ev.EventType, ev.Data.Resource.Status)
	if !ok {
		return nil, fmt.Errorf("wise: unhandled event %q", ev.EventType)
	}
	return &PayoutWebhookEvent{
		Type:              mapped,
		ExternalAccountID: string(ev.Data.Resource.ID),
		Activated:         mapped == PayoutEventAccountActivated,
		RawEventID:        ev.EventID,
	}, nil
}

// mapWiseTransferEvent maps a transfers#state-change current_state to
// the normalized transfer taxonomy. Non-terminal states are Ignored so
// the webhook is ACKed without dispatching.
// IsAccountActive fetches GET /v1/accounts/{id} — the reconciliation
// step before activating a recipient, since recipients#state-change
// carries no activation flag.
func (p *WiseProvider) IsAccountActive(ctx context.Context, accountID string) (bool, error) {
	var resp struct {
		ID     json.Number `json:"id"`
		Active bool        `json:"active"`
	}
	if err := p.getJSON(ctx, "/v1/accounts/"+accountID, &resp); err != nil {
		return false, fmt.Errorf("wise recipient status: %w", err)
	}
	return resp.Active, nil
}

var wiseUUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// wiseIdempotencyUUID satisfies Wise's requirement that
// customerTransactionId be a UUID: a caller key that already is one
// passes through (lower-cased); anything else derives a deterministic
// RFC 4122 name-based UUID from the key, so the same caller key always
// yields the same customerTransactionId and Wise dedupe still holds.
func wiseIdempotencyUUID(key string) string {
	if wiseUUIDRe.MatchString(key) {
		return strings.ToLower(key)
	}
	sum := sha256.Sum256([]byte("keel-wise-ctid:" + key))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5 (name-based)
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func mapWiseTransferEvent(state string) PayoutWebhookEventType {
	switch mapWiseTransferStatus(state) {
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

func mapWiseEvent(name, status string) (PayoutWebhookEventType, bool) {
	switch name {
	case "recipients#created":
		return PayoutEventAccountCreated, true
	case "recipients#updated":
		if status == "ACTIVE" {
			return PayoutEventAccountActivated, true
		}
		return PayoutEventAccountUpdated, true
	case "recipients#deleted":
		return PayoutEventAccountRejected, true
	}
	return "", false
}

var _ PayoutProvider = (*WiseProvider)(nil)
