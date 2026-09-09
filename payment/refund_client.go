package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type RefundStatus string

// ErrRefundAmountMismatch accompanies a RefundResult whose provider amount
// differs from the request; the refund exists and must be reconciled, not retried.
var ErrRefundAmountMismatch = errors.New("refund: provider amount differs from request")

const (
	RefundPending   RefundStatus = "pending"
	RefundSucceeded RefundStatus = "succeeded"
	RefundFailed    RefundStatus = "failed"
)

// RefundRequest refunds part or all of a captured payment. AmountMinor is in
// minor units; Currency guards against refunding in the wrong currency.
type RefundRequest struct {
	PaymentID      string // provider payment reference (Stripe pi_…)
	AmountMinor    int64
	Currency       string
	IdempotencyKey string
	Reason         string // provider-defined; Stripe: duplicate | fraudulent | requested_by_customer
	Metadata       map[string]string
}

type RefundResult struct {
	RefundID    string
	Status      RefundStatus
	AmountMinor int64
	Currency    string
}

// RefundClient is the outbound half of refund handling; the inbound half is
// the parser's charge.refunded event, which reports refunds as negative
// MinorUnits and the cumulative amount_refunded.
type RefundClient interface {
	CreateRefund(ctx context.Context, req RefundRequest) (RefundResult, error)
}

type stripeRefundResponse struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
	Error    *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *StripeChargeClient) CreateRefund(ctx context.Context, req RefundRequest) (RefundResult, error) {
	if c == nil || c.Stripe == nil {
		return RefundResult{}, fmt.Errorf("refund: stripe client is required")
	}
	switch {
	case req.PaymentID == "":
		return RefundResult{}, fmt.Errorf("refund: PaymentID is required")
	case req.AmountMinor <= 0:
		return RefundResult{}, fmt.Errorf("refund: AmountMinor must be positive")
	case req.IdempotencyKey == "":
		return RefundResult{}, fmt.Errorf("refund: IdempotencyKey is required")
	case len(strings.TrimSpace(req.Currency)) != 3:
		return RefundResult{}, fmt.Errorf("refund: Currency must be an ISO 4217 code")
	case req.Reason != "" && req.Reason != "duplicate" && req.Reason != "fraudulent" && req.Reason != "requested_by_customer":
		return RefundResult{}, fmt.Errorf("refund: unsupported reason %q", req.Reason)
	}
	if err := validateMetadata(req.Metadata); err != nil {
		return RefundResult{}, err
	}
	paymentBody, err := c.Stripe.Get(ctx, "/payment_intents/"+url.PathEscape(req.PaymentID), nil)
	if err != nil {
		return RefundResult{}, fmt.Errorf("refund: read payment: %w", err)
	}
	var payment struct {
		Currency string `json:"currency"`
	}
	if err := json.Unmarshal(paymentBody, &payment); err != nil || payment.Currency == "" {
		return RefundResult{}, fmt.Errorf("refund: payment currency unavailable")
	}
	if !strings.EqualFold(req.Currency, payment.Currency) {
		return RefundResult{}, fmt.Errorf("refund: currency %s does not match payment currency %s", req.Currency, payment.Currency)
	}
	form := url.Values{
		"payment_intent": {req.PaymentID},
		"amount":         {strconv.FormatInt(req.AmountMinor, 10)},
	}
	if req.Reason != "" {
		form.Set("reason", req.Reason)
	}
	setMetadata(form, req.Metadata)
	status, body, err := c.Stripe.PostRaw(ctx, "/refunds", form, req.IdempotencyKey)
	if err != nil {
		return RefundResult{}, err
	}
	var parsed stripeRefundResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return RefundResult{}, fmt.Errorf("refund: parse response: %w", err)
	}
	if status < 200 || status >= 300 {
		code := ""
		if parsed.Error != nil {
			code = parsed.Error.Code
		}
		return RefundResult{}, fmt.Errorf("refund: stripe %d %s", status, code)
	}
	if !strings.EqualFold(req.Currency, parsed.Currency) {
		return RefundResult{}, fmt.Errorf("refund: currency %s does not match payment currency %s", req.Currency, parsed.Currency)
	}
	if parsed.ID == "" {
		return RefundResult{}, fmt.Errorf("refund: incomplete provider response")
	}
	result := RefundResult{RefundID: parsed.ID, AmountMinor: parsed.Amount, Currency: strings.ToUpper(parsed.Currency)}
	switch parsed.Status {
	case "succeeded":
		result.Status = RefundSucceeded
	case "pending", "requires_action":
		result.Status = RefundPending
	case "failed", "canceled":
		result.Status = RefundFailed
	default:
		return RefundResult{}, fmt.Errorf("refund: unknown provider status %q", parsed.Status)
	}
	if parsed.Amount != req.AmountMinor {
		return result, ErrRefundAmountMismatch
	}
	return result, nil
}

var _ RefundClient = (*StripeChargeClient)(nil)
