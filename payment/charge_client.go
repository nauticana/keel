package payment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ChargeStatus is the normalized outcome of an off-session charge.
type ChargeStatus string

const (
	ChargeSucceeded      ChargeStatus = "succeeded"
	ChargeRequiresAction ChargeStatus = "requires_action" // off-session SCA/3DS needed
	ChargeFailed         ChargeStatus = "failed"
)

// ChargeRequest is one off-session charge against a stored credential.
type ChargeRequest struct {
	CustomerToken      string // provider customer id (Stripe cus_xxx)
	PaymentMethodToken string // provider payment-method id (Stripe pm_xxx) — off-session charges need a specific stored method
	AmountMinor        int64  // minor currency units (e.g. cents)
	Currency           string // ISO 4217 (any case)
	IdempotencyKey     string // de-dupe key — use the invoice id
	Description        string
}

// ChargeResult is the normalized outcome of ChargeClient.Charge.
type ChargeResult struct {
	Status           ChargeStatus
	ProviderChargeID string // PaymentIntent / charge id (pi_xxx)
	ClientSecret     string // PI client_secret — for the project to build an SCA confirmation page when Status==requires_action
	ActionURL        string // a provider-hosted redirect URL when one exists (often empty for off-session 3DS)
	Error            string // decline / error message when failed
}

// ChargeClient charges a partner's saved (vaulted) payment method off-session.
// It is the lowest-common-denominator primitive that lets a project run its OWN
// billing cycle (self-scheduled) against any provider that can charge a stored
// credential — keeping self-scheduled billing provider-agnostic.
type ChargeClient interface {
	// Charge attempts an off-session charge. A hard provider/transport error is
	// returned as err; a decline or SCA-required outcome is reported via
	// ChargeResult.Status with err == nil so the caller runs its dunning / SCA
	// path rather than aborting.
	Charge(ctx context.Context, req ChargeRequest) (ChargeResult, error)
}

// StripeChargeClient implements ChargeClient via Stripe PaymentIntents created
// off_session=true, confirm=true against the customer's stored payment method.
type StripeChargeClient struct {
	Stripe *StripeCheckoutClient
}

type stripeNextAction struct {
	RedirectToURL *struct {
		URL string `json:"url"`
	} `json:"redirect_to_url"`
}

// stripeChargeResponse covers BOTH the 2xx PaymentIntent body and the 4xx
// error envelope (which carries the PaymentIntent under error.payment_intent).
type stripeChargeResponse struct {
	ID           string            `json:"id"`
	Status       string            `json:"status"`
	ClientSecret string            `json:"client_secret"`
	NextAction   *stripeNextAction `json:"next_action"`
	Error        *struct {
		Code          string `json:"code"`
		Message       string `json:"message"`
		PaymentIntent *struct {
			ID           string            `json:"id"`
			Status       string            `json:"status"`
			ClientSecret string            `json:"client_secret"`
			NextAction   *stripeNextAction `json:"next_action"`
		} `json:"payment_intent"`
	} `json:"error"`
}

func actionURL(na *stripeNextAction) string {
	if na != nil && na.RedirectToURL != nil {
		return na.RedirectToURL.URL
	}
	return ""
}

func (c *StripeChargeClient) Charge(ctx context.Context, req ChargeRequest) (ChargeResult, error) {
	form := url.Values{
		"amount":      {strconv.FormatInt(req.AmountMinor, 10)},
		"currency":    {strings.ToLower(req.Currency)},
		"customer":    {req.CustomerToken},
		"off_session": {"true"},
		"confirm":     {"true"},
	}
	if req.PaymentMethodToken != "" {
		form.Set("payment_method", req.PaymentMethodToken)
	}
	if req.Description != "" {
		form.Set("description", req.Description)
	}
	if req.IdempotencyKey != "" {
		// Also carry the key in metadata for human reconciliation in the Stripe
		// dashboard; the real dedupe is the Idempotency-Key header set below.
		form.Set("metadata[idempotency_key]", req.IdempotencyKey)
	}

	// Pass the caller's operation-scoped key (the invoice id) as Stripe's
	// Idempotency-Key so a charge retried after an ambiguous transport failure
	// resolves to the ORIGINAL PaymentIntent instead of creating a second one.
	// Stripe remembers a key for 24h; a dunning retry scheduled beyond that
	// window is treated as new, so the engine must still stop charging once the
	// invoice flips to paid.
	status, body, err := c.Stripe.PostRaw(ctx, "/payment_intents", form, req.IdempotencyKey)
	if err != nil {
		return ChargeResult{}, err // transport / exhausted retries — caller retries later
	}

	var resp stripeChargeResponse
	_ = json.Unmarshal(body, &resp) // defensive; missing fields stay zero

	if status >= 200 && status < 300 {
		res := ChargeResult{ProviderChargeID: resp.ID, ClientSecret: resp.ClientSecret}
		switch resp.Status {
		case "succeeded", "processing":
			res.Status = ChargeSucceeded
		case "requires_action", "requires_confirmation":
			res.Status = ChargeRequiresAction
			res.ActionURL = actionURL(resp.NextAction)
		default:
			res.Status = ChargeFailed
		}
		return res, nil
	}

	// Non-2xx: a decline or an off-session authentication_required error. Stripe
	// puts the PaymentIntent under error.payment_intent in that case.
	if resp.Error != nil {
		pi := resp.Error.PaymentIntent
		authRequired := resp.Error.Code == "authentication_required" ||
			(pi != nil && pi.Status == "requires_action")
		if authRequired {
			res := ChargeResult{Status: ChargeRequiresAction}
			if pi != nil {
				res.ProviderChargeID = pi.ID
				res.ClientSecret = pi.ClientSecret
				res.ActionURL = actionURL(pi.NextAction)
			}
			return res, nil
		}
		res := ChargeResult{Status: ChargeFailed, Error: resp.Error.Message}
		if pi != nil {
			res.ProviderChargeID = pi.ID
		}
		return res, nil
	}
	return ChargeResult{Status: ChargeFailed, Error: fmt.Sprintf("stripe charge failed: status %d", status)}, nil
}

var _ ChargeClient = (*StripeChargeClient)(nil)
