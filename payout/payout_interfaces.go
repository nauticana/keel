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
	"encoding/json"
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

	// Transfer lifecycle — asynchronous outcomes of a previously
	// dispatched payout, keyed by ProviderTransferID. Downstream ledgers
	// consume these via OnboardingService.TransferSink.
	PayoutEventTransferPaid     PayoutWebhookEventType = "transfer.paid"
	PayoutEventTransferFailed   PayoutWebhookEventType = "transfer.failed"
	PayoutEventTransferReturned PayoutWebhookEventType = "transfer.returned"
	PayoutEventTransferReversed PayoutWebhookEventType = "transfer.reversed"

	// PayoutEventIgnored marks a verified, well-formed event the
	// integration recognizes but has nothing to apply for (e.g. a
	// non-terminal transfer state). The webhook is ACKed so the provider
	// stops retrying; nothing is dispatched.
	PayoutEventIgnored PayoutWebhookEventType = "ignored"
)

// PayoutWebhookEvent is the normalized webhook payload after the
// provider's own envelope/signature/version handling has been stripped.
// Account events populate ExternalAccountID; transfer events populate
// ProviderTransferID.
type PayoutWebhookEvent struct {
	Type               PayoutWebhookEventType
	ExternalAccountID  string
	ProviderTransferID string // provider transfer/payout id for transfer.* events
	Activated          bool   // true when the provider's KYC is fully cleared and payouts can run
	RawEventID         string // provider's event id (or a deterministic synthesis), for idempotency / dedupe
	OccurredAt         string // provider's event timestamp when supplied — sinks use it for out-of-order delivery

	// Reversal amounts (minor units), populated when the provider reports
	// them. A transfer.reversed with AmountReversedMinor < AmountMinor is
	// a PARTIAL reversal — sinks must claw back only the reversed amount,
	// never assume the whole payout reversed.
	AmountMinor         int64
	AmountReversedMinor int64
}

// AccountStatusChecker is the optional provider capability to fetch the
// live activation state of a destination account, for providers whose
// webhooks carry no activation flag (Wise recipients#state-change).
type AccountStatusChecker interface {
	IsAccountActive(ctx context.Context, accountID string) (bool, error)
}

// BeneficiaryCreator is the optional provider capability to register a
// payout destination from application-collected details (Airwallex
// embedded beneficiary component). Details pass through to the provider;
// keel stores only the returned id.
type BeneficiaryCreator interface {
	CreateBeneficiary(ctx context.Context, beneficiary json.RawMessage) (string, error)
}

// PayoutResumer is the optional provider capability for recovering a
// multi-leg payout whose funding leg succeeded but whose payout leg
// failed or was lost: it runs ONLY the missing leg against the persisted
// funding id, so recovery can never re-fund. Downstream workers
// type-assert it on their PayoutProvider.
type PayoutResumer interface {
	ResumePayout(ctx context.Context, in InstantPayoutInput, fundingID string) (*InstantPayoutResult, error)
}

// TransferEventSink receives normalized transfer-lifecycle events so the
// downstream payout ledger can move its state machine on authoritative
// provider outcomes. Implementations must be idempotent — the webhook
// log deduplicates event ids, but reconciliation polling may re-apply
// the same terminal state.
type TransferEventSink interface {
	ApplyTransferEvent(ctx context.Context, ev *PayoutWebhookEvent) error
}

// WebhookLog is the durable event-id idempotency record for payout
// webhooks, backed by the basis payout_webhook_log table. Financial
// events must never rely on a process-local or expiring cache.
//
// Claim atomically records the event for processing: duplicate=true
// when the event was already processed or is currently in flight.
// A previously FAILED delivery (and an abandoned in-flight claim) is
// re-claimed instead — a transient sink outage must never permanently
// swallow a financial event.
type WebhookLog interface {
	Claim(ctx context.Context, provider string, ev *PayoutWebhookEvent, rawBody []byte) (logID int64, duplicate bool, err error)
	UpdateStatus(ctx context.Context, logID int64, status, message string) error
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

// InstantPayoutResult echoes the provider's view of the payout. Status
// is the normalized lifecycle code; downstream apps switch on it for
// their own status columns. "paid" means the provider explicitly
// returned a paid state — never infer completion from creation alone.
// "paid" is NOT guaranteed final on every provider: Airwallex documents
// that a PAID transfer can later become FAILED, so sinks and ledgers
// must accept a paid → failed/returned/reversed transition.
//
// ProviderFundingID names the funding leg when disbursement is
// multi-step (Stripe: the platform transfer tr_…; Wise: same as the
// payout id). Persist BOTH ids BEFORE dispatch completes: reversal
// webhooks reference the funding leg, and a multi-step provider may
// return a non-nil result ALONGSIDE an error when a later leg failed —
// the ids are what reconciliation needs to resume or reverse.
//
// Retry semantics are bounded by provider idempotency retention
// (Stripe documents ~24h): within retention, retrying with the SAME
// key is safe (both legs dedupe); a cached terminal error keeps
// returning that error. Beyond retention — or to escape a cached
// error — do NOT re-run the full operation with any key: when a
// funding id is persisted but no payout id, use the provider's
// PayoutResumer capability (Stripe implements it) to run only the
// missing leg; minting a new key for the full operation double-funds.
type InstantPayoutResult struct {
	ProviderPayoutID  string
	ProviderFundingID string
	Status            string // "pending" / "paid" / "failed" / "returned" / "reversed"
	EstimatedArrival  string
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

// ErrInstantPayoutUnavailable is the typed error for destinations that
// cannot receive the instant rail (e.g. Stripe accounts without an
// instant-eligible external account). Callers fall back to a standard
// schedule or surface a precise message.
var ErrInstantPayoutUnavailable = errors.New("payout: instant payout not available for this destination")

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

	// GetPayoutStatus fetches the provider's current view of a
	// previously created transfer/payout by its provider id — the
	// reconciliation path when webhooks are missed. Provider
	// idempotency-key retention is finite; look up before blindly
	// reissuing an expired key.
	GetPayoutStatus(ctx context.Context, providerPayoutID string) (*InstantPayoutResult, error)
}
