// Package payout abstracts the third-party providers that hold bank
// routing details and disburse out-bound payouts to partner users.
// Downstream applications never see raw IBAN / SWIFT / ABA / institution
// numbers — only the provider's account handle (ExternalAccountID) and
// a normalized event taxonomy.
//
// Pluggable providers ship as separate files in this package
// (airwallex.go, stripe_connect.go, wise.go). New providers implement
// PayoutProvider and register themselves in factory.go.
package payout

import (
	"context"
	"errors"
)

// PayoutOnboardingSession is what a provider returns when the caller
// asks to start the hosted KYC / bank-routing collection flow. URL is
// opened in a webview / browser; the provider's own UI walks the user
// through bank details, creates an external account, and then fires
// the configured webhook back at the application.
//
// ExternalAccountID is the provider's placeholder handle returned at
// session-start time. Some providers (Airwallex, Stripe Connect) create
// the account synchronously and hand the ID back immediately; others
// (Wise) defer creation until the user submits the form. Either way,
// the application persists this value if non-empty so that the later
// webhook can be matched even before activation.
type PayoutOnboardingSession struct {
	URL               string
	ExternalAccountID string
	ExpiresAt         string
}

// PayoutWebhookEventType is the normalized event taxonomy that every
// provider impl maps its raw events into. Service layer never looks at
// provider-native event names.
type PayoutWebhookEventType string

const (
	PayoutEventAccountCreated   PayoutWebhookEventType = "account.created"
	PayoutEventAccountActivated PayoutWebhookEventType = "account.activated"
	PayoutEventAccountUpdated   PayoutWebhookEventType = "account.updated"
	PayoutEventAccountRejected  PayoutWebhookEventType = "account.rejected"
)

// PayoutWebhookEvent is the normalized webhook payload after the
// provider's own envelope/signature/version handling has been stripped.
type PayoutWebhookEvent struct {
	Type              PayoutWebhookEventType
	ExternalAccountID string
	Activated         bool   // true when the provider's KYC is fully cleared and payouts can run
	RawEventID        string // provider's event id, for idempotency / dedupe
}

// StartOnboardingInput is the per-user context the provider needs to
// create a new external account. Most providers want country + currency
// for routing rules; some (Stripe Connect) also need a return URL to
// redirect back to the calling application after the hosted form.
type StartOnboardingInput struct {
	UserID         int64
	PartnerID      int64
	CountryCode    string
	Currency       string
	AccountHolder  string
	BillingAddress string
	ReturnURL      string
	NotifyURL      string // server-side webhook callback URL
}

// InstantPayoutInput requests an out-of-cycle payout to the user's
// configured external account. Fee, minimum, cooldown, and balance
// pre-checks belong to the caller (downstream policy), not the
// provider — the provider just executes the transfer and reports
// success or a typed failure.
//
// Amount is in minor currency units (e.g. cents for USD / CAD / EUR;
// JPY has no minor units so use whole-yen integers). IdempotencyKey is
// a caller-supplied dedupe key the provider stores for at least 24h to
// reject double-spends.
type InstantPayoutInput struct {
	UserID            int64
	PartnerID         int64
	ProviderAccountID string // pre-resolved by the service layer
	Amount            int64  // minor units
	Currency          string
	IdempotencyKey    string
}

// InstantPayoutResult echoes the provider's view of the in-flight
// payout. Status is the normalized lifecycle code; downstream apps
// switch on it for their own status columns.
type InstantPayoutResult struct {
	ProviderPayoutID string
	Status           string // "pending" / "paid" / "failed"
	EstimatedArrival string
}

// ErrInsufficientBalance is the typed error every provider returns
// when the source-of-funds balance is below the requested amount.
// Callers catch this specifically to surface a clean "top up first"
// message rather than a generic transfer failure.
var ErrInsufficientBalance = errors.New("payout: insufficient balance")

// ErrNotImplemented is returned by provider impls that have not yet
// wired a given method (typically RequestInstantPayout on a provider
// whose integration is still pending).
var ErrNotImplemented = errors.New("payout: provider method not implemented")

// PayoutProvider is the pluggable contract for any third-party that
// holds bank routing details and runs out-bound payouts. The downstream
// application never sees raw routing numbers / IBANs / SWIFT — only the
// provider's account handle (ExternalAccountID).
//
// Code returns the 2-char provider code (e.g. "AW" Airwallex,
// "SC" Stripe Connect, "WI" Wise). The webhook router dispatches
// incoming events to the right impl based on this code.
type PayoutProvider interface {
	// Code returns the 2-char provider identifier persisted on the
	// user_bank_info.provider column. Stable across releases.
	Code() string

	// StartOnboarding kicks off the provider's hosted KYC flow and
	// returns the URL the calling application opens for the user.
	StartOnboarding(ctx context.Context, in StartOnboardingInput) (*PayoutOnboardingSession, error)

	// VerifyAndParseWebhook checks the provider's signature header
	// against the raw body, then normalizes the payload into a
	// PayoutWebhookEvent. Returns an error if the signature is bad,
	// the event type is not one the integration handles, or the body
	// is malformed.
	VerifyAndParseWebhook(headers map[string][]string, rawBody []byte) (*PayoutWebhookEvent, error)

	// RequestInstantPayout requests an out-of-cycle transfer of Amount
	// to the user's ProviderAccountID. Returns ErrInsufficientBalance
	// when the source-of-funds balance is below Amount, ErrNotImplemented
	// when the provider does not yet support instant payouts.
	RequestInstantPayout(ctx context.Context, in InstantPayoutInput) (*InstantPayoutResult, error)
}
