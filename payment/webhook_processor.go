package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/logger"
)

// ErrPermanent wraps webhook-processing errors that the provider
// should NOT retry — bad signature, malformed body, unknown provider,
// etc. The HTTP handler maps these to 4xx so Stripe / LemonSqueezy
// stop retrying immediately. Anything not wrapped in ErrPermanent is
// treated as transient and bubbles up as 5xx (provider retries on
// its standard schedule).
//
//	if errors.Is(err, payment.ErrPermanent) { /* return 4xx */ }
var ErrPermanent = errors.New("permanent webhook error")

// permanentErr wraps cause with ErrPermanent so callers can detect
// the class via errors.Is. Message stays under their control.
func permanentErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrPermanent}, args...)...)
}

// WebhookProcessor owns the full webhook lifecycle:
//
//	log → idempotency → signature verify → parse → handler → status update.
//
// It is provider-agnostic: the same instance handles every registered
// PaymentProvider. Projects implement port.PaymentEventHandler to map the
// canonical PaymentEvent into their domain actions.
type WebhookProcessor struct {
	Repo      WebhookRepository
	Providers map[string]PaymentProvider
	Journal   logger.ApplicationLogger // optional
}

// NewWebhookProcessor constructs a processor and registers the given
// providers by their Name().
func NewWebhookProcessor(repo WebhookRepository, journal logger.ApplicationLogger, providers ...PaymentProvider) *WebhookProcessor {
	p := &WebhookProcessor{
		Repo:      repo,
		Journal:   journal,
		Providers: make(map[string]PaymentProvider, len(providers)),
	}
	for _, pr := range providers {
		p.Providers[pr.Name()] = pr
	}
	return p
}

// Register adds or replaces a provider at runtime.
func (p *WebhookProcessor) Register(provider PaymentProvider) {
	if p.Providers == nil {
		p.Providers = map[string]PaymentProvider{}
	}
	p.Providers[provider.Name()] = provider
}

// Provider returns the registered provider with that name, or nil.
func (p *WebhookProcessor) Provider(name string) PaymentProvider {
	if p.Providers == nil {
		return nil
	}
	return p.Providers[name]
}

// Process runs a full webhook lifecycle for providerName.
//
// Order of operations is load-bearing — every step before the handler
// is a defense against a specific class of attack:
//
//  1. Reject when the body has no event id. Synthetic-id fallbacks
//     would defeat idempotency: each replay would mint a fresh id and
//     re-enter the handler. Reject upstream so retries get a 4xx and
//     the provider's own dedupe never fires under us.
//
//  2. VERIFY the signature BEFORE writing to the DB. The previous
//     "log first, verify second" ordering let an unauthenticated
//     attacker fill payment_webhook_log with arbitrary 256 KiB blobs
//     by hammering the endpoint with garbage. Now an unsigned request
//     never touches storage; legitimate provider retries always re-
//     verify and re-log.
//
//  3. Look up an existing row by (provider, event_id). Any hit means
//     a prior delivery of the same event already reached us — even if
//     it's still in status 'R' (in flight) — so the handler MUST NOT
//     run a second time. Charge-twice prevention.
//
//  4. Insert with a unique-index-backed write. If two concurrent
//     deliveries both passed step 3 (TOCTOU window), one of the
//     inserts will fail with a uniqueness violation; we treat that
//     as a duplicate and bail.
//
//  5. Parse + dispatch the canonical event to the domain handler;
//     update status accordingly.
func (p *WebhookProcessor) Process(
	ctx context.Context,
	providerName string,
	sigHeader string,
	body []byte,
	handler PaymentEventHandler,
) error {
	provider := p.Provider(providerName)
	if provider == nil {
		// Unknown provider is a configuration bug, not a transient
		// outage — there is no scenario in which retrying succeeds.
		return permanentErr("unknown payment provider %q", providerName)
	}

	// (1) Pull event id + type out of the raw body. We don't trust the
	// payload yet — but extractEventMeta only reads a couple of fields.
	eventID, eventType, parseErr := extractEventMeta(provider.Name(), body)
	if parseErr != nil {
		// Surface the underlying JSON-decode error in the journal so
		// operators don't have to debug "missing event id" messages
		// when the actual cause is a malformed body.
		p.logError("payment.Process: malformed webhook body for provider %q: %v", provider.Name(), parseErr)
		return permanentErr("malformed webhook body: %v", parseErr)
	}
	if eventID == "" {
		return permanentErr("missing event id; refusing to log unidentified webhook")
	}

	// (2) Verify the signature against the still-untrusted body. Writes
	// nothing on failure — keeps payment_webhook_log clean of unsigned
	// junk. Bad signatures are permanent: a retry of the same payload
	// fails the same way.
	if err := provider.Verify(ctx, sigHeader, body); err != nil {
		return permanentErr("signature verification failed: %v", err)
	}

	// (3) Cheap path: did we already see this event id?
	seen, err := p.Repo.Exists(ctx, provider.Name(), eventID)
	if err != nil {
		return fmt.Errorf("payment.Process exists: %w", err)
	}
	if seen {
		return nil
	}

	// (4) Authoritative race guard: insert with the unique index on
	// (provider, event_id). A concurrent retry that snuck past step 3
	// loses this race and returns a uniqueness error; treat that as
	// duplicate and exit cleanly.
	logID, err := p.Repo.Log(ctx, provider.Name(), eventID, eventType, body)
	if err != nil {
		if isUniqueViolation(err) {
			return nil
		}
		p.logError("payment.Process log: %v", err)
		return err
	}

	// (5) Parse + dispatch. Errors here flip the row to 'F' and bubble
	// up so the provider can retry — but only the parse/handle step is
	// retryable, never verify (a real attacker can't get past it) and
	// never log (idempotency rejects a re-attempt).
	event, err := provider.Parse(body)
	if err != nil {
		_ = p.Repo.UpdateStatus(ctx, logID, StatusFailed, err.Error())
		// Parse failures are permanent: the same payload won't
		// suddenly become parseable on retry.
		return permanentErr("parse event: %v", err)
	}
	if event == nil {
		_ = p.Repo.UpdateStatus(ctx, logID, StatusProcessed, "")
		return nil
	}
	event.Provider = provider.Name()

	if err := handler.OnPaymentEvent(ctx, event); err != nil {
		_ = p.Repo.UpdateStatus(ctx, logID, StatusFailed, err.Error())
		return fmt.Errorf("handle event: %w", err)
	}

	_ = p.Repo.UpdateStatus(ctx, logID, StatusProcessed, "")
	return nil
}

// isUniqueViolation reports whether err is a Postgres unique-index
// violation. Uses a typed errors.As against pgconn.PgError + the
// canonical SQLSTATE code 23505 (MAJOR 11). The previous substring
// match on "duplicate"/"unique" could false-positive on a domain
// trigger raising `RAISE EXCEPTION 'duplicate ...'`, silently
// skipping a real failure as an "already-seen" idempotent webhook.
//
// MySQL / SQLite consumers can layer their own driver-specific
// detection on top — keel is pgsql-only at the data layer.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

func (p *WebhookProcessor) logError(format string, args ...any) {
	if p.Journal != nil {
		p.Journal.Error(fmt.Sprintf(format, args...))
	}
}

// extractEventMeta peeks at the raw body to get the provider event ID +
// type. Needed before Parse() because the idempotency check fires
// before the full canonical Parse runs. The peek decoder unmarshals
// only 2-4 fields, so the marginal CPU cost vs the subsequent Parse()
// (which decodes the full event) is dominated by the second pass —
// not worth changing the EventParser interface to collapse for the
// O(10) events/sec a typical webhook stream sustains.
//
// Returns a non-nil error when the body is not valid JSON so callers
// can distinguish "malformed body" from "valid JSON without an id".
// Operators previously had to guess at the root cause when both
// branches reported "missing event id".
func extractEventMeta(provider string, body []byte) (eventID, eventType string, err error) {
	switch provider {
	case "stripe":
		var peek struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if err = json.Unmarshal(body, &peek); err != nil {
			return "", "", err
		}
		return peek.ID, peek.Type, nil
	case "lemonsqueezy":
		var peek struct {
			Meta struct {
				EventName string `json:"event_name"`
			} `json:"meta"`
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err = json.Unmarshal(body, &peek); err != nil {
			return "", "", err
		}
		return peek.Data.ID, peek.Meta.EventName, nil
	}
	return "", "", nil
}
