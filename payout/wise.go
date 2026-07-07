package payout

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
// Wise signs webhook bodies with plain SHA-256 of `secret || body`
// (NOT HMAC) per the Wise Platform spec, so AbstractProvider's
// hmacSHA256Hex helper is not used here.
//
// apiBase comes from wise_api_base (default sandbox host).
// profileID comes from wise_profile_id (required at boot).
type WiseProvider struct {
	AbstractProvider
	apiBase    string
	profileID  string
	httpClient *http.Client
}

func NewWiseProvider(apiKey, webhookSecret string, journal logger.ApplicationLogger) (*WiseProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("wise: API key is required")
	}
	return &WiseProvider{
		AbstractProvider: AbstractProvider{
			apiKey:        apiKey,
			webhookSecret: webhookSecret,
			journal:       journal,
		},
		apiBase:    common.Config().WiseAPIBase,
		profileID:  common.Config().WiseProfileID,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (p *WiseProvider) Code() string { return ProviderCodeWise }

// wiseRecipientReq is the POST /v1/accounts request body for an
// email-type recipient. Wise expects camelCase JSON fields. The
// profile field is the numeric platform profile id (Wise rejects
// requests without one).
type wiseRecipientReq struct {
	Currency          string         `json:"currency"`
	Type              string         `json:"type"`
	Profile           string         `json:"profile"`
	AccountHolderName string         `json:"accountHolderName"`
	Details           map[string]any `json:"details"`
}

type wiseRecipientResp struct {
	ID int64 `json:"id"`
}

// StartOnboarding creates a Wise email-type recipient. There's no
// hosted KYC URL to return — Wise emails the recipient a claim link
// directly and they confirm asynchronously, at which point the
// recipients#updated webhook fires with status="ACTIVE". URL stays
// empty so sail's frontend treats this as "linked, awaiting claim".
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

	req := wiseRecipientReq{
		Currency:          strings.ToUpper(in.Currency),
		Type:              "email",
		Profile:           p.profileID,
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

type wiseQuoteReq struct {
	SourceCurrency string `json:"sourceCurrency"`
	TargetCurrency string `json:"targetCurrency"`
	SourceAmount   *int64 `json:"sourceAmount,omitempty"`
	TargetAmount   *int64 `json:"targetAmount,omitempty"`
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

// RequestInstantPayout creates a Wise quote + transfer.
//
// The transfer is NOT funded by this method — Wise's funding API
// (POST /v3/profiles/{profile}/transfers/{id}/payments) requires a
// separate authorization flow (SCA + funding source selection) that
// keel doesn't currently surface. The created transfer sits in
// status="incoming_payment_waiting" until the platform funds it from
// the Wise dashboard or via a downstream funding worker.
//
// For instant payouts where the platform wants single-call execution,
// downstream apps should layer a funding call on top of this method —
// see the Wise Platform docs for the SCA challenge handling.
//
// IdempotencyKey rides in customerTransactionId per Wise's spec; Wise
// dedupes on this within the platform profile.
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

	// Quote first — Wise rejects /v1/transfers without a quote uuid.
	srcAmt := in.Amount
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
		CustomerTransactionID: in.IdempotencyKey,
	}
	var tResp wiseTransferResp
	if err := p.postJSON(ctx, "/v1/transfers", transfer, &tResp); err != nil {
		if isWiseInsufficientBalance(err) {
			return nil, ErrInsufficientBalance
		}
		return nil, fmt.Errorf("wise payout transfer: %w", err)
	}
	return &InstantPayoutResult{
		ProviderPayoutID: fmt.Sprintf("%d", tResp.ID),
		Status:           mapWiseTransferStatus(tResp.Status),
		EstimatedArrival: tResp.EstimatedDelivery,
	}, nil
}

func mapWiseTransferStatus(s string) string {
	switch strings.ToLower(s) {
	case "incoming_payment_waiting", "processing", "funds_converted":
		return "pending"
	case "outgoing_payment_sent":
		return "paid"
	case "cancelled", "bounced_back", "funds_refunded":
		return "failed"
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

type wiseWebhookEvent struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	Data      struct {
		Resource struct {
			ID     string `json:"id"`
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"resource"`
	} `json:"data"`
}

func (p *WiseProvider) VerifyAndParseWebhook(headers map[string][]string, rawBody []byte) (*PayoutWebhookEvent, error) {
	sig := firstHeader(headers, "x-signature-sha256")
	if sig == "" {
		return nil, fmt.Errorf("wise: missing X-Signature-SHA256 header")
	}
	if p.webhookSecret == "" {
		return nil, fmt.Errorf("wise: webhook secret not configured")
	}
	sum := sha256.Sum256(append([]byte(p.webhookSecret), rawBody...))
	expected := fmt.Sprintf("%x", sum[:])
	if subtle.ConstantTimeCompare([]byte(expected), []byte(sig)) != 1 {
		return nil, fmt.Errorf("wise: invalid signature")
	}

	var ev wiseWebhookEvent
	if err := json.Unmarshal(rawBody, &ev); err != nil {
		return nil, fmt.Errorf("wise: parse: %w", err)
	}
	mapped, ok := mapWiseEvent(ev.EventType, ev.Data.Resource.Status)
	if !ok {
		return nil, fmt.Errorf("wise: unhandled event %q", ev.EventType)
	}
	return &PayoutWebhookEvent{
		Type:              mapped,
		ExternalAccountID: ev.Data.Resource.ID,
		Activated:         mapped == PayoutEventAccountActivated,
		RawEventID:        ev.EventID,
	}, nil
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
