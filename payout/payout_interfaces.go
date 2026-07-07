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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/nauticana/keel/logger"
)

// Provider code constants — the 2-char identifiers persisted on
// user_bank_info.provider and routed on by the webhook handler. Downstream
// code MUST use these constants rather than literal "AW" / "SC" / "WI" so
// a future rename touches one place. They also match what the
// payout_provider flag in common/variables.go accepts.
const (
	ProviderCodeAirwallex     = "AW"
	ProviderCodeStripeConnect = "SC"
	ProviderCodeWise          = "WI"
)

// AbstractProvider is the base implementation shared by every concrete
// PayoutProvider impl. It holds the three fields every provider needs
// (apiKey, webhookSecret, journal) plus a small HMAC-SHA256 helper used
// during webhook signature verification.
//
// Concrete providers embed AbstractProvider by value at the top of their
// struct declaration so field promotion makes apiKey / webhookSecret /
// journal accessible directly (p.apiKey, not p.AbstractProvider.apiKey).
// The Code() method stays on each concrete because it's the one piece of
// state the abstract layer cannot supply.
type AbstractProvider struct {
	apiKey        string
	webhookSecret string
	journal       logger.ApplicationLogger
}

// hmacSHA256Hex computes HMAC-SHA256(webhookSecret, parts...) and returns
// it as lower-case hex — the wire format both Airwallex and Stripe Connect
// expect on their signature headers. Returns the empty string when
// webhookSecret is unset so callers can short-circuit with a clear "secret
// not configured" error rather than producing a misleading signature
// mismatch.
//
// The variadic parts argument lets each provider feed the components of
// its signed payload in order. Airwallex and Stripe both sign
// "<timestamp>.<body>"; Wise signs the body alone but uses plain SHA256
// (not HMAC), so Wise does NOT use this helper.
func (p *AbstractProvider) hmacSHA256Hex(parts ...[]byte) string {
	if p.webhookSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(p.webhookSecret))
	for _, part := range parts {
		mac.Write(part)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// PayoutOnboardingSession is what a provider returns when the caller
// asks to start the hosted KYC / bank-routing collection flow.
//
// URL is opened in a webview / browser; the provider's own UI walks the
// user through bank details, creates an external account, and then fires
// the configured webhook back at the application. URL is EMPTY for
// providers whose model has no hosted flow (Wise's recipient model —
// the calling app shows "linked" and the recipient confirms via email).
//
// ExternalAccountID is the provider's account handle. Airwallex and
// Stripe Connect create the account synchronously and return the id at
// session-start time; Wise returns the recipient id from its
// recipient-create response. The application persists this value if
// non-empty so the later webhook (or first transfer) can be matched even
// before activation.
//
// ExpiresAt is the provider's RFC3339 timestamp for when the hosted URL
// or recipient handle expires — kept as a string and passed through
// unchanged. The wire shape (sail consumes `json:"expiresAt"` as a
// string) is part of the public contract; do not promote this to
// time.Time without coordinating with sail and downstream consumers.
// Empty when the provider returns no expiry (Wise) or has no concept
// of one.
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
//
// Email is loaded by OnboardingService.loadBankInfo via a JOIN to
// user_account. Stripe Connect requires it on the Express account at
// creation time; Wise uses it as the recipient identifier when type=email.
// Airwallex passes it through as metadata. Empty Email is a configuration
// error for Stripe Connect and Wise (they reject the request);
// Airwallex tolerates it.
type StartOnboardingInput struct {
	UserID         int64
	PartnerID      int64
	Email          string
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
