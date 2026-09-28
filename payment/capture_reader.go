package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// CapturedPayment is the amount a provider actually captured for a payment,
// the ceiling every refund against it is bounded by.
type CapturedPayment struct {
	AmountMinor int64
	Currency    string
}

// CaptureReader reads a payment's captured amount. Apps that already store
// the captured amount can implement it locally instead of asking the provider.
type CaptureReader interface {
	CapturedAmount(ctx context.Context, paymentID string) (CapturedPayment, error)
}

func (c *StripeChargeClient) CapturedAmount(ctx context.Context, paymentID string) (CapturedPayment, error) {
	if c == nil || c.Stripe == nil {
		return CapturedPayment{}, fmt.Errorf("captured amount: stripe client is required")
	}
	if paymentID == "" {
		return CapturedPayment{}, fmt.Errorf("captured amount: payment id is required")
	}
	body, err := c.Stripe.Get(ctx, "/payment_intents/"+url.PathEscape(paymentID), nil)
	if err != nil {
		return CapturedPayment{}, fmt.Errorf("captured amount: read payment: %w", err)
	}
	var intent struct {
		AmountReceived int64  `json:"amount_received"`
		Currency       string `json:"currency"`
	}
	if err := json.Unmarshal(body, &intent); err != nil {
		return CapturedPayment{}, fmt.Errorf("captured amount: parse payment: %w", err)
	}
	if intent.Currency == "" {
		return CapturedPayment{}, ErrRefundCapturedAmountAbsent
	}
	return CapturedPayment{AmountMinor: intent.AmountReceived, Currency: strings.ToUpper(intent.Currency)}, nil
}

var _ CaptureReader = (*StripeChargeClient)(nil)
