package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ChargeStatus is the normalized outcome of an off-session charge or authorization.
type ChargeStatus string

const (
	ChargeSucceeded      ChargeStatus = "succeeded"
	ChargeAuthorized     ChargeStatus = "authorized"      // the hold is placed and awaits Capture
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
	Metadata           map[string]string // forwarded onto the provider charge and surfaced back on its PaymentEvent.Metadata so a webhook can correlate it
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

// ErrInvalidMetadata is returned before any network call when request metadata
// violates the provider's limits. Map it to a 4xx at the handler boundary.
var ErrInvalidMetadata = errors.New("payment: invalid charge metadata")

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
	Status              ChargeStatus
	ProviderChargeID    string        // PaymentIntent / charge id (pi_xxx)
	ClientSecret        string        // PI client_secret: requires_action runs its next_action; authentication_required re-confirms with PaymentMethodID (Stripe.js confirmCardPayment, stripe-ios STPPaymentHandler.confirmPayment)
	PaymentMethodID     string        // stored method to re-confirm with when Status==authentication_required
	ActionURL           string        // a provider-hosted redirect URL when one exists (often empty for off-session 3DS)
	Error               string        // decline / error message when failed
	DeclineReason       DeclineReason // set when a failure carries a provider decline
	ProviderDeclineCode string        // the provider's raw decline code, for logs
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

type stripePaymentIntent struct {
	ID               string            `json:"id"`
	Status           string            `json:"status"`
	ClientSecret     string            `json:"client_secret"`
	AmountCapturable int64             `json:"amount_capturable"`
	AmountReceived   int64             `json:"amount_received"`
	NextAction       *stripeNextAction `json:"next_action"`
	LatestCharge     json.RawMessage   `json:"latest_charge"` // an id, or the charge object when expanded
	LastPaymentError *stripeError      `json:"last_payment_error"`
}

type stripeError struct {
	Code          string                  `json:"code"`
	DeclineCode   string                  `json:"decline_code"`
	Message       string                  `json:"message"`
	PaymentMethod *stripePaymentMethodRef `json:"payment_method"`
	PaymentIntent *stripePaymentIntent    `json:"payment_intent"`
}

// stripeChargeResponse covers BOTH the 2xx PaymentIntent body and the 4xx
// error envelope (which carries the PaymentIntent under error.payment_intent).
type stripeChargeResponse struct {
	stripePaymentIntent
	Error *stripeError `json:"error"`
}

func actionURL(na *stripeNextAction) string {
	if na != nil && na.RedirectToURL != nil {
		return na.RedirectToURL.URL
	}
	return ""
}

func (c *StripeChargeClient) Charge(ctx context.Context, req ChargeRequest) (ChargeResult, error) {
	res, _, err := c.confirm(ctx, req, false)
	return res, err
}

// confirm creates and confirms an off-session PaymentIntent, automatic or
// manual capture, and returns the PaymentIntent it reports on, if any.
func (c *StripeChargeClient) confirm(ctx context.Context, req ChargeRequest, manual bool) (ChargeResult, *stripePaymentIntent, error) {
	if err := validateMetadata(req.Metadata); err != nil {
		return ChargeResult{}, nil, err
	}
	form := url.Values{
		"amount":      {strconv.FormatInt(req.AmountMinor, 10)},
		"currency":    {strings.ToLower(req.Currency)},
		"customer":    {req.CustomerToken},
		"off_session": {"true"},
		"confirm":     {"true"},
	}
	if manual {
		form.Set("capture_method", "manual")
		form.Set("payment_method_options[card][request_incremental_authorization]", "if_available")
		form.Set("expand[]", "latest_charge")
	}
	if req.PaymentMethodToken != "" {
		form.Set("payment_method", req.PaymentMethodToken)
	}
	if req.Description != "" {
		form.Set("description", req.Description)
	}
	setMetadata(form, req.Metadata)
	if req.IdempotencyKey != "" {
		// Dashboard reconciliation only; the Idempotency-Key header is the real
		// dedupe. Set last so the reserved key always wins.
		form.Set("metadata["+reservedMetadataKey+"]", req.IdempotencyKey)
	}

	// The operation-scoped key makes a retry after an ambiguous transport
	// failure resolve to the ORIGINAL PaymentIntent. Stripe remembers a key for
	// 24h; a dunning retry beyond that is new, so the engine must stop charging
	// once the invoice flips to paid.
	status, body, err := c.Stripe.PostRaw(ctx, "/payment_intents", form, req.IdempotencyKey)
	if err != nil {
		return ChargeResult{}, nil, err // transport / exhausted retries — caller retries later
	}
	var resp stripeChargeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return ChargeResult{}, nil, fmt.Errorf("stripe charge: decode response: %w", err)
	}
	if is2xx(status) {
		return intentResult(&resp.stripePaymentIntent, manual), &resp.stripePaymentIntent, nil
	}
	if resp.Error == nil {
		return ChargeResult{Status: ChargeFailed, Error: fmt.Sprintf("stripe charge failed: status %d", status)}, nil, nil
	}
	// Non-2xx: a decline or an off-session authentication_required error.
	e, pi := resp.Error, resp.Error.PaymentIntent
	if pi != nil && pi.Status == "requires_action" {
		return intentResult(pi, manual), pi, nil
	}
	if e.Code == "authentication_required" {
		res := ChargeResult{Status: ChargeAuthenticationRequired}
		if e.PaymentMethod != nil {
			res.PaymentMethodID = e.PaymentMethod.ID
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
		return res, pi, nil
	}
	// Only a 402 is a card decline; a 400 is a request error with no decline reason.
	res := ChargeResult{Status: ChargeFailed, Error: e.Message}
	if status == http.StatusPaymentRequired {
		res = declineResult(e)
	}
	if pi != nil {
		res.ProviderChargeID = pi.ID
	}
	return res, pi, nil
}

// intentResult maps a PaymentIntent body; manual expects requires_capture
// where an automatic-capture charge expects succeeded.
func intentResult(pi *stripePaymentIntent, manual bool) ChargeResult {
	res := ChargeResult{ProviderChargeID: pi.ID, ClientSecret: pi.ClientSecret}
	switch {
	case pi.Status == "requires_action":
		res.Status = ChargeRequiresAction
		res.ActionURL = actionURL(pi.NextAction)
	case manual && pi.Status == "requires_capture":
		res.Status = ChargeAuthorized
	case !manual && (pi.Status == "succeeded" || pi.Status == "processing"):
		res.Status = ChargeSucceeded
	case pi.LastPaymentError != nil:
		res = declineResult(pi.LastPaymentError)
		res.ProviderChargeID = pi.ID
	default:
		res.Status = ChargeFailed
		res.Error = "unexpected PaymentIntent status " + pi.Status
	}
	return res
}

func declineResult(e *stripeError) ChargeResult {
	code := e.DeclineCode
	if code == "" {
		code = e.Code
	}
	return ChargeResult{Status: ChargeFailed, Error: e.Message, DeclineReason: stripeDeclineReason(code), ProviderDeclineCode: code}
}

func stripeDeclineReason(code string) DeclineReason {
	switch code {
	case "":
		return ""
	case "insufficient_funds":
		return DeclineInsufficientFunds
	case "expired_card":
		return DeclineExpiredCard
	case "incorrect_cvc", "invalid_cvc":
		return DeclineIncorrectCVC
	case "processing_error":
		return DeclineProcessingError
	case "payment_intent_authentication_failure", "authentication_required":
		return DeclineAuthenticationFailed
	case "card_declined", "generic_decline", "do_not_honor", "lost_card", "stolen_card",
		"pickup_card", "restricted_card", "transaction_not_allowed", "card_not_supported":
		return DeclineCardDeclined
	}
	return DeclineOther
}

var _ ChargeClient = (*StripeChargeClient)(nil)
