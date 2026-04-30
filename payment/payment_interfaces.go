package payment

import (
	"context"
	"time"
)

// PaymentEvent is the canonical representation of a webhook event after
// provider-specific parsing. Domain handlers receive this and decide what to
// persist for their project.
//
// Money: prefer MinorUnits over Amount. Amount is a float64 for
// backwards source-compat with consumers that read it directly, but
// floats accumulate rounding error across reconciliation passes and
// cannot represent every cent value exactly. MinorUnits is the
// integer minor-currency value (e.g. 1999 for $19.99 USD; 1500 for
// ¥1500 JPY which has no minor unit). Reconciliation, ledger, and
// accounting code MUST use MinorUnits.
//
// Sign: refunds carry a NEGATIVE MinorUnits / Amount; zero-amount
// events (setup-mode checkouts, payment failures) carry zero. The
// previous parser silently filtered amount==0 / amount<0 — that's
// fixed (P1-11) and consumers must now handle the full value range.
type PaymentEvent struct {
	Provider        string  // "stripe" | "lemonsqueezy"
	ProviderEventID string  // idempotency key
	EventType       string  // "checkout.session.completed", etc.
	Amount          float64 // DEPRECATED — major units, lossy for accounting. Prefer MinorUnits.
	MinorUnits      int64   // integer minor-currency units (e.g. cents). Authoritative.
	Currency        string  // upper-case ISO 4217
	PaidAt          time.Time
	RawPayload      string            // original JSON, for audit / replay
	Metadata        map[string]string // provider's metadata field, flattened to strings
}

// PaymentEventHandler is what each project implements. keel's
// WebhookProcessor calls OnPaymentEvent after signature verification and
// idempotency checks succeed.
type PaymentEventHandler interface {
	OnPaymentEvent(ctx context.Context, e *PaymentEvent) error
}

// CheckoutRequest is what a project hands to CheckoutClient.CreateCheckoutSession
// when it wants to redirect a user to the hosted checkout page.
type CheckoutRequest struct {
	Mode       string // "subscription" | "payment" | "setup"
	PriceID    string // provider price ID (Stripe price_xxx); required except when Mode=="setup"
	Quantity   int64
	Email      string
	SuccessURL string
	CancelURL  string
	Metadata   map[string]string // written into provider's checkout metadata
}

// SignatureVerifier validates a webhook signature for a specific provider.
// Implementations own the secret lookup, replay window, and algorithm.
type SignatureVerifier interface {
	Verify(ctx context.Context, sigHeader string, body []byte) error
}

// EventParser converts a raw provider webhook body into a canonical
// PaymentEvent. Implementations own the provider's schema.
type EventParser interface {
	Parse(body []byte) (*PaymentEvent, error)
}

// PaymentProvider bundles everything needed to process webhooks for a
// single provider: its name, signature header, verifier, and parser.
// Projects register one or more providers with the WebhookProcessor.
type PaymentProvider interface {
	Name() string
	SignatureHeader() string // e.g. "Stripe-Signature"
	SignatureVerifier
	EventParser
}

// WebhookRepository persists webhook log rows — the idempotency and audit
// store. Separated from the processor so consumers can back it with any
// storage (SQL, in-memory for tests, NoSQL, etc.).
type WebhookRepository interface {
	Log(ctx context.Context, provider, eventID, eventType string, rawBody []byte) (logID int64, err error)
	Exists(ctx context.Context, provider, eventID string) (bool, error)
	UpdateStatus(ctx context.Context, logID int64, status string, message string) error
}

// CheckoutClient abstracts outbound calls to a payment provider's
// checkout / billing-portal API. Stripe, LemonSqueezy, etc. each get an
// implementation; projects inject whichever they need.
type CheckoutClient interface {
	CreateCheckoutSession(ctx context.Context, req CheckoutRequest) (url string, err error)
	CreatePortalSession(ctx context.Context, customerID, returnURL string) (url string, err error)
}
