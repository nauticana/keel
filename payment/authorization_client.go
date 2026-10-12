package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ErrIncrementNotSupported: the card or provider cannot raise this hold;
// capture it and charge the difference separately.
var ErrIncrementNotSupported = errors.New("payment: incremental authorization not supported")

// AuthorizationResult is the outcome of placing or raising a hold.
type AuthorizationResult struct {
	ChargeResult
	AmountAuthorizedMinor int64     // currently held and capturable
	ExpiresAt             time.Time // capture deadline; zero when the provider reports none
}

// AuthorizationClient holds an amount on a stored credential and settles it
// later. As with Charge, a decline or SCA outcome is reported in the result
// with err == nil.
type AuthorizationClient interface {
	// Authorize places an off-session hold; success is ChargeAuthorized.
	Authorize(ctx context.Context, req ChargeRequest) (AuthorizationResult, error)
	// Capture takes up to the authorized amount; the remainder is released.
	Capture(ctx context.Context, paymentID string, amountMinor int64, idempotencyKey string) error
	// IncrementAuthorization raises the hold to newAmountMinor, or returns
	// ErrIncrementNotSupported. A declined raise leaves the previous hold.
	IncrementAuthorization(ctx context.Context, paymentID string, newAmountMinor int64, idempotencyKey string) (AuthorizationResult, error)
	// CancelAuthorization releases the hold; an already released one is success.
	CancelAuthorization(ctx context.Context, paymentID, reason string) error
}

func (c *StripeChargeClient) Authorize(ctx context.Context, req ChargeRequest) (AuthorizationResult, error) {
	res, pi, err := c.confirm(ctx, req, true)
	if err != nil {
		return AuthorizationResult{}, err
	}
	return authorizationResult(res, pi)
}

func (c *StripeChargeClient) Capture(ctx context.Context, paymentID string, amountMinor int64, idempotencyKey string) error {
	if amountMinor <= 0 || idempotencyKey == "" {
		return fmt.Errorf("capture: positive amount and idempotency key are required")
	}
	status, resp, err := c.postIntent(ctx, paymentID, "capture", url.Values{"amount_to_capture": {strconv.FormatInt(amountMinor, 10)}}, idempotencyKey)
	if err != nil {
		return err
	}
	if !is2xx(status) {
		return stripeIntentError("capture", status, resp.Error)
	}
	if resp.Status != "succeeded" {
		return fmt.Errorf("capture: payment %s is %s", paymentID, resp.Status)
	}
	return nil
}

func (c *StripeChargeClient) IncrementAuthorization(ctx context.Context, paymentID string, newAmountMinor int64, idempotencyKey string) (AuthorizationResult, error) {
	if newAmountMinor <= 0 || idempotencyKey == "" {
		return AuthorizationResult{}, fmt.Errorf("increment authorization: positive amount and idempotency key are required")
	}
	if err := c.ready("increment authorization", paymentID); err != nil {
		return AuthorizationResult{}, err
	}
	body, err := c.Stripe.Get(ctx, "/payment_intents/"+url.PathEscape(paymentID), url.Values{"expand[]": {"latest_charge"}})
	if err != nil {
		return AuthorizationResult{}, fmt.Errorf("increment authorization: read payment: %w", err)
	}
	var current stripePaymentIntent
	if err := json.Unmarshal(body, &current); err != nil {
		return AuthorizationResult{}, fmt.Errorf("increment authorization: parse payment: %w", err)
	}
	if current.Status != "requires_capture" {
		return AuthorizationResult{}, fmt.Errorf("increment authorization: payment %s is %s", paymentID, current.Status)
	}
	card, err := stripeChargeCard(current.LatestCharge)
	if err != nil {
		return AuthorizationResult{}, fmt.Errorf("increment authorization: %w", err)
	}
	if card.IncrementalAuthorization.Status != "available" {
		return AuthorizationResult{}, ErrIncrementNotSupported
	}
	form := url.Values{"amount": {strconv.FormatInt(newAmountMinor, 10)}, "expand[]": {"latest_charge"}}
	status, resp, err := c.postIntent(ctx, paymentID, "increment_authorization", form, idempotencyKey)
	if err != nil {
		return AuthorizationResult{}, err
	}
	if is2xx(status) {
		return authorizationResult(intentResult(&resp.stripePaymentIntent, true), &resp.stripePaymentIntent)
	}
	if status != http.StatusPaymentRequired || resp.Error == nil {
		return AuthorizationResult{}, stripeIntentError("increment authorization", status, resp.Error)
	}
	res := declineResult(resp.Error)
	res.ProviderChargeID = paymentID
	held := resp.Error.PaymentIntent
	if held == nil {
		held = &current
	}
	return authorizationResult(res, held)
}

var stripeCancellationReasons = map[string]bool{"": true, "duplicate": true, "fraudulent": true, "requested_by_customer": true, "abandoned": true}

func (c *StripeChargeClient) CancelAuthorization(ctx context.Context, paymentID, reason string) error {
	if !stripeCancellationReasons[reason] {
		return fmt.Errorf("cancel authorization: unsupported reason %q", reason)
	}
	form := url.Values{}
	if reason != "" {
		form.Set("cancellation_reason", reason)
	}
	status, resp, err := c.postIntent(ctx, paymentID, "cancel", form, "")
	if err != nil {
		return err
	}
	if is2xx(status) || resp.Error != nil && resp.Error.PaymentIntent != nil && resp.Error.PaymentIntent.Status == "canceled" {
		return nil
	}
	return stripeIntentError("cancel authorization", status, resp.Error)
}

// postIntent posts a PaymentIntent action; err is set only for transport or decode failures.
func (c *StripeChargeClient) postIntent(ctx context.Context, paymentID, action string, form url.Values, idempotencyKey string) (int, stripeChargeResponse, error) {
	var resp stripeChargeResponse
	if err := c.ready(action, paymentID); err != nil {
		return 0, resp, err
	}
	status, body, err := c.Stripe.PostRaw(ctx, "/payment_intents/"+url.PathEscape(paymentID)+"/"+action, form, idempotencyKey)
	if err != nil {
		return 0, resp, fmt.Errorf("%s: %w", action, err)
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, resp, fmt.Errorf("%s: decode response: %w", action, err)
	}
	return status, resp, nil
}

func (c *StripeChargeClient) ready(op, paymentID string) error {
	if c == nil || c.Stripe == nil {
		return fmt.Errorf("%s: stripe client is required", op)
	}
	if paymentID == "" {
		return fmt.Errorf("%s: payment id is required", op)
	}
	return nil
}

func authorizationResult(res ChargeResult, pi *stripePaymentIntent) (AuthorizationResult, error) {
	out := AuthorizationResult{ChargeResult: res}
	if pi == nil {
		return out, nil
	}
	out.AmountAuthorizedMinor = pi.AmountCapturable
	card, err := stripeChargeCard(pi.LatestCharge)
	if err != nil {
		return AuthorizationResult{}, fmt.Errorf("authorize: %w", err)
	}
	if card.CaptureBefore > 0 {
		out.ExpiresAt = time.Unix(card.CaptureBefore, 0).UTC()
	}
	return out, nil
}

type stripeCardDetails struct {
	CaptureBefore            int64 `json:"capture_before"`
	IncrementalAuthorization struct {
		Status string `json:"status"`
	} `json:"incremental_authorization"`
}

// stripeChargeCard reads the card details of an expanded latest_charge; a bare charge id or null yields none.
func stripeChargeCard(raw json.RawMessage) (stripeCardDetails, error) {
	var charge struct {
		PaymentMethodDetails struct {
			Card stripeCardDetails `json:"card"`
		} `json:"payment_method_details"`
	}
	if len(raw) == 0 || raw[0] != '{' {
		return stripeCardDetails{}, nil
	}
	if err := json.Unmarshal(raw, &charge); err != nil {
		return stripeCardDetails{}, fmt.Errorf("parse latest_charge: %w", err)
	}
	return charge.PaymentMethodDetails.Card, nil
}

func stripeIntentError(op string, status int, e *stripeError) error {
	if e == nil {
		return fmt.Errorf("%s: stripe %d", op, status)
	}
	return fmt.Errorf("%s: stripe %d %s: %s", op, status, e.Code, e.Message)
}

func is2xx(status int) bool { return status >= 200 && status < 300 }

var _ AuthorizationClient = (*StripeChargeClient)(nil)
