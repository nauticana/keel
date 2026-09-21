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

// ChargeStatus is the normalized outcome of an off-session charge.
type ChargeStatus string

const (
	ChargeSucceeded      ChargeStatus = "succeeded"
	ChargeRequiresAction ChargeStatus = "requires_action" // PaymentIntent carries a next_action to run
	// ChargeAuthenticationRequired: the off-session confirmation was refused for
	// SCA. The PaymentIntent has no next_action; the customer must come
	// on-session and confirm it again with ChargeResult.PaymentMethodID.
	ChargeAuthenticationRequired ChargeStatus = "authentication_required"
	ChargeFailed                 ChargeStatus = "failed"
)

// ChargeRequest is one off-session charge against a stored credential.
type ChargeRequest struct {
	CustomerToken      string            // provider customer id (Stripe cus_xxx)
	PaymentMethodToken string            // provider payment-method id (Stripe pm_xxx) — off-session charges need a specific stored method
	AmountMinor        int64             // minor currency units (e.g. cents)
	Currency           string            // ISO 4217 (any case)
	IdempotencyKey     string            // de-dupe key — use the invoice id
	Description        string            // free-text shown on the provider charge
	Metadata           map[string]string // arbitrary key/value pairs forwarded onto the provider charge (Stripe PaymentIntent metadata); surfaced back on the settled charge's PaymentEvent.Metadata so a webhook can correlate it to the originating record
}

// Stripe metadata limits (https://stripe.com/docs/api/metadata): at most 50
// keys, key names up to 40 chars, values up to 500 chars. The charge client
// reserves one key (idempotency_key) for reconciliation, so callers get 49.
const (
	maxMetadataPairs    = 49
	maxMetadataKeyLen   = 40
	maxMetadataValLen   = 500
	reservedMetadataKey = "idempotency_key"
)

// ErrInvalidMetadata is returned by ChargeClient.Charge before any network call
// when ChargeRequest.Metadata violates the provider's metadata constraints.
// It is a caller (programming) error, so the charge is rejected loudly rather
// than silently truncated. Map it to a 4xx at the handler boundary.
var ErrInvalidMetadata = errors.New("payment: invalid charge metadata")

// validateMetadata enforces the provider's metadata limits and protects the
// reserved reconciliation key. It does not mutate the request.
func validateMetadata(md map[string]string) error {
	if len(md) > maxMetadataPairs {
		return fmt.Errorf("%w: %d pairs exceeds limit of %d", ErrInvalidMetadata, len(md), maxMetadataPairs)
	}
	for k, v := range md {
		if k == "" {
			return fmt.Errorf("%w: empty key", ErrInvalidMetadata)
		}
		if k == reservedMetadataKey {
			return fmt.Errorf("%w: key %q is reserved", ErrInvalidMetadata, reservedMetadataKey)
		}
		if len(k) > maxMetadataKeyLen {
			return fmt.Errorf("%w: key %q exceeds %d chars", ErrInvalidMetadata, k, maxMetadataKeyLen)
		}
		if len(v) > maxMetadataValLen {
			return fmt.Errorf("%w: value for key %q exceeds %d chars", ErrInvalidMetadata, k, maxMetadataValLen)
		}
	}
	return nil
}

// ChargeResult is the normalized outcome of ChargeClient.Charge.
type ChargeResult struct {
	Status           ChargeStatus
	ProviderChargeID string // PaymentIntent / charge id (pi_xxx)
	ClientSecret     string // PI client_secret: requires_action runs its next_action; authentication_required re-confirms with PaymentMethodID (Stripe.js confirmCardPayment, stripe-ios STPPaymentHandler.confirmPayment)
	PaymentMethodID  string // stored method to re-confirm with when Status==authentication_required
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

type stripePaymentMethodRef struct {
	ID string `json:"id"`
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
		Code          string                  `json:"code"`
		Message       string                  `json:"message"`
		PaymentMethod *stripePaymentMethodRef `json:"payment_method"`
		PaymentIntent *struct {
			ID               string            `json:"id"`
			Status           string            `json:"status"`
			ClientSecret     string            `json:"client_secret"`
			NextAction       *stripeNextAction `json:"next_action"`
			LastPaymentError *struct {
				PaymentMethod *stripePaymentMethodRef `json:"payment_method"`
			} `json:"last_payment_error"`
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
	if err := validateMetadata(req.Metadata); err != nil {
		return ChargeResult{}, err
	}
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
	for k, v := range req.Metadata {
		form.Set("metadata["+k+"]", v)
	}
	if req.IdempotencyKey != "" {
		// Also carry the key in metadata for human reconciliation in the Stripe
		// dashboard; the real dedupe is the Idempotency-Key header set below.
		// Set last so the reserved key always wins (validateMetadata also
		// rejects callers trying to supply it themselves).
		form.Set("metadata["+reservedMetadataKey+"]", req.IdempotencyKey)
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
	if err := json.Unmarshal(body, &resp); err != nil {
		return ChargeResult{}, fmt.Errorf("stripe charge: decode response: %w", err)
	}

	if status >= 200 && status < 300 {
		res := ChargeResult{ProviderChargeID: resp.ID, ClientSecret: resp.ClientSecret}
		switch resp.Status {
		case "succeeded", "processing":
			res.Status = ChargeSucceeded
		case "requires_action":
			res.Status = ChargeRequiresAction
			res.ActionURL = actionURL(resp.NextAction)
		default:
			res.Status = ChargeFailed
			res.Error = "unexpected PaymentIntent status " + resp.Status
		}
		return res, nil
	}

	// Non-2xx: a decline or an off-session authentication_required error. Stripe
	// puts the PaymentIntent under error.payment_intent in that case.
	if resp.Error != nil {
		pi := resp.Error.PaymentIntent
		if pi != nil && pi.Status == "requires_action" {
			return ChargeResult{
				Status:           ChargeRequiresAction,
				ProviderChargeID: pi.ID,
				ClientSecret:     pi.ClientSecret,
				ActionURL:        actionURL(pi.NextAction),
			}, nil
		}
		if resp.Error.Code == "authentication_required" {
			res := ChargeResult{Status: ChargeAuthenticationRequired}
			if resp.Error.PaymentMethod != nil {
				res.PaymentMethodID = resp.Error.PaymentMethod.ID
			}
			if pi != nil {
				res.ProviderChargeID = pi.ID
				res.ClientSecret = pi.ClientSecret
				if res.PaymentMethodID == "" && pi.LastPaymentError != nil && pi.LastPaymentError.PaymentMethod != nil {
					res.PaymentMethodID = pi.LastPaymentError.PaymentMethod.ID
				}
			}
			if res.PaymentMethodID == "" {
				res.PaymentMethodID = req.PaymentMethodToken
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
