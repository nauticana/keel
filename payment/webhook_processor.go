package payment

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
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

const (
	defaultWebhookReplayLimit       = 50
	defaultWebhookReplayMaxAttempts = 5

	webhookMetricTotal    = "keel_payment_webhooks_total"
	webhookMetricDuration = "keel_payment_webhook_duration_seconds"

	webhookModeDelivery = "delivery"
	webhookModeReplay   = "replay"

	webhookOutcomeProcessed    = "processed"
	webhookOutcomeFailed       = "failed"
	webhookOutcomeDeadLettered = "dead_lettered"
	webhookOutcomeSkipped      = "skipped"
	webhookOutcomeDuplicate    = "duplicate"
	webhookOutcomeRejected     = "rejected"
)

// WebhookReplayOptions bounds one operator-initiated RetryFailed sweep.
// Zero values use a 50-row limit and five replay attempts.
type WebhookReplayOptions struct {
	Limit       int
	MaxAttempts int
}

// WebhookReplaySummary reports the terminal result of each row claimed by one
// RetryFailed sweep.
type WebhookReplaySummary struct {
	Claimed      int
	Processed    int
	Skipped      int
	Failed       int
	DeadLettered int
}

// permanentErr wraps cause with ErrPermanent so callers can detect
// the class via errors.Is. Message stays under their control.
func permanentErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrPermanent}, args...)...)
}

// WebhookProcessor owns the full webhook lifecycle:
//
//	peek → signature verify → idempotency → log → parse → handler → status update.
//
// It is provider-agnostic: the same instance handles every registered
// PaymentProvider. Projects implement PaymentEventHandler to map the
// canonical PaymentEvent into their domain actions.
type WebhookProcessor struct {
	Repo      WebhookRepository
	Providers map[string]PaymentProvider
	Journal   logger.ApplicationLogger // optional
	Metrics   port.MetricsRecorder     // optional

	// AllowedEventTypes, when non-nil, gates which (provider, event_type)
	// pairs reach the domain handler. Events not in the set are logged
	// with status='S' (skipped) and never dispatched. nil means "trust
	// the dashboard" — every signed event reaches the handler, which
	// is the v0.5.0 behavior.
	//
	// Wire via WithAllowedEventTypes("checkout.session.completed",
	// "setup_intent.succeeded", ...) at startup so an operator who
	// accidentally subscribes a noisy event in the Stripe dashboard
	// (customer.created, customer.updated) doesn't push that event
	// through the domain layer (downstream feedback v0.5.1-E).
	AllowedEventTypes map[string]bool

	// AfterHandler, when non-nil, is invoked after a successful
	// OnPaymentEvent. Use it for cross-cutting follow-ups that aren't
	// part of the canonical event mapping — typically an idempotent
	// Stripe POST like POST /v1/payment_methods/{id}/attach to make a
	// freshly-saved PaymentMethod the customer's default. A non-nil
	// error from AfterHandler flips the log row to status='F' so the
	// provider retries the whole pipeline; AfterHandler MUST therefore
	// be idempotent (downstream feedback v0.5.1-F).
	AfterHandler func(ctx context.Context, event *PaymentEvent) error
}

// WithAllowedEventTypes sets the per-event-type allowlist on the
// processor and returns the receiver for fluent construction.
//
//	processor := payment.NewWebhookProcessor(repo, journal, stripeProvider).
//	    WithAllowedEventTypes(
//	        "checkout.session.completed",
//	        "setup_intent.succeeded",
//	        "invoice.paid",
//	    )
func (p *WebhookProcessor) WithAllowedEventTypes(types ...string) *WebhookProcessor {
	if p.AllowedEventTypes == nil {
		p.AllowedEventTypes = make(map[string]bool, len(types))
	}
	for _, t := range types {
		p.AllowedEventTypes[t] = true
	}
	return p
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
//     a prior delivery of the same event already reached us, so the
//     handler must not run again — except a failed row, or an 'R' row
//     whose claim lease expired (crashed mid-dispatch), which this
//     redelivery atomically re-claims. Charge-twice prevention.
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
) (err error) {
	started := time.Now()
	eventType := ""
	outcome := webhookOutcomeFailed
	defer func() {
		p.recordWebhookMetrics(ctx, providerName, eventType, webhookModeDelivery, outcome, time.Since(started))
	}()

	if p.Repo == nil {
		return fmt.Errorf("payment.Process: webhook repository is not configured")
	}
	provider := p.Provider(providerName)
	if provider == nil {
		// Unknown provider is a configuration bug, not a transient
		// outage — there is no scenario in which retrying succeeds.
		outcome = webhookOutcomeRejected
		return permanentErr("unknown payment provider %q", providerName)
	}
	providerName = provider.Name()

	// (1) Pull event id + type out of the raw body via the provider's
	// own peek implementation. We don't trust the payload yet — but
	// PeekEventMeta only reads a couple of fields. Provider-specific
	// schema knowledge stays in the parser; the processor only sees
	// the polymorphic interface.
	eventID, eventType, parseErr := provider.PeekEventMeta(body)
	if parseErr != nil {
		// Surface the underlying JSON-decode error in the journal so
		// operators don't have to debug "missing event id" messages
		// when the actual cause is a malformed body.
		outcome = webhookOutcomeRejected
		p.logError(ctx, "payment.Process: malformed webhook body for provider %q: %v", provider.Name(), parseErr)
		return permanentErr("malformed webhook body: %v", parseErr)
	}
	if eventID == "" {
		outcome = webhookOutcomeRejected
		return permanentErr("missing event id; refusing to log unidentified webhook")
	}

	// (2) Verify the signature against the still-untrusted body. Writes
	// nothing on failure — keeps payment_webhook_log clean of unsigned
	// junk. Bad signatures are permanent: a retry of the same payload
	// fails the same way.
	if err := provider.Verify(ctx, sigHeader, body); err != nil {
		outcome = webhookOutcomeRejected
		return permanentErr("signature verification failed: %v", err)
	}

	// (3) Cheap path: did we already see this event id?
	seen, err := p.Repo.Exists(ctx, provider.Name(), eventID)
	if err != nil {
		return fmt.Errorf("payment.Process exists: %w", err)
	}
	if seen {
		// A prior delivery exists. If it ended in StatusFailed — or sits
		// in StatusReceived past its claim lease (crashed mid-dispatch) —
		// and the repository supports reclaim, atomically re-claim it so
		// this retry re-runs the handler; otherwise the event would be
		// stranded forever (provider retries all short-circuit here).
		// Terminal rows, live in-flight rows, and repos that don't
		// implement WebhookReclaimer fall through to a no-op skip.
		reclaimer, ok := p.Repo.(WebhookReclaimer)
		if !ok {
			outcome = webhookOutcomeDuplicate
			return nil
		}
		logID, claimed, err := reclaimer.ReclaimFailed(ctx, provider.Name(), eventID)
		if err != nil {
			return fmt.Errorf("payment.Process reclaim: %w", err)
		}
		if !claimed {
			outcome = webhookOutcomeDuplicate
			return nil
		}
		outcome, err = p.dispatch(ctx, provider, logID, eventType, body, handler, false, StatusFailed)
		return err
	}

	// (4) Authoritative race guard: insert with the unique index on
	// (provider, event_id). A concurrent retry that snuck past step 3
	// loses this race and returns a uniqueness error; treat that as
	// duplicate and exit cleanly.
	logID, err := p.Repo.Log(ctx, provider.Name(), eventID, eventType, common.RequestIDFromContext(ctx), body)
	if err != nil {
		if isUniqueViolation(err) {
			outcome = webhookOutcomeDuplicate
			return nil
		}
		p.logError(ctx, "payment.Process log: %v", err)
		return err
	}

	outcome, err = p.dispatch(ctx, provider, logID, eventType, body, handler, false, StatusFailed)
	return err
}

// RetryFailed runs an explicit replay sweep over previously verified failed
// deliveries. It does not verify the provider signature again: Stripe's signed
// timestamp is expected to have expired, while the immutable payload already
// crossed that boundary before it was persisted.
//
// Each row is claimed at most once per sweep and only for registered
// providers; the SQL repository also spaces attempts on the same row by a
// claim lease, covering overlapping sweeps, and recovers claims abandoned by
// a crash. A failed final attempt moves to L (dead-letter), which neither
// provider redelivery nor later sweeps reclaim. Handlers can distinguish
// this path through PaymentEvent.ReplayMode.
func (p *WebhookProcessor) RetryFailed(
	ctx context.Context,
	handler PaymentEventHandler,
	options WebhookReplayOptions,
) (WebhookReplaySummary, error) {
	var summary WebhookReplaySummary
	if p.Repo == nil {
		return summary, fmt.Errorf("payment.RetryFailed: webhook repository is not configured")
	}
	if handler == nil {
		return summary, fmt.Errorf("payment.RetryFailed: event handler is not configured")
	}
	providers := slices.Sorted(maps.Keys(p.Providers))
	if len(providers) == 0 {
		return summary, fmt.Errorf("payment.RetryFailed: no payment providers registered")
	}
	if options.Limit <= 0 {
		options.Limit = defaultWebhookReplayLimit
	}
	if options.MaxAttempts <= 0 {
		options.MaxAttempts = defaultWebhookReplayMaxAttempts
	}

	var replayErrors []error
	var cursor int64
	for summary.Claimed < options.Limit {
		if err := ctx.Err(); err != nil {
			replayErrors = append(replayErrors, err)
			break
		}
		delivery, claimed, err := p.Repo.ClaimFailed(ctx, options.MaxAttempts, cursor, providers)
		if err != nil {
			replayErrors = append(replayErrors, fmt.Errorf("payment.RetryFailed claim: %w", err))
			break
		}
		if !claimed {
			break
		}
		cursor = delivery.LogID
		summary.Claimed++

		replayCtx := ctx
		if common.RequestIDFromContext(replayCtx) == "" {
			replayCtx = common.WithRequestID(replayCtx, delivery.RequestID)
		}
		started := time.Now()
		if delivery.DeadLettered {
			summary.DeadLettered++
			p.recordWebhookMetrics(
				replayCtx,
				delivery.Provider,
				delivery.EventType,
				webhookModeReplay,
				webhookOutcomeDeadLettered,
				time.Since(started),
			)
			continue
		}
		failureStatus := StatusFailed
		if delivery.ReplayAttempts >= options.MaxAttempts {
			failureStatus = StatusDeadLetter
		}

		outcome := webhookOutcomeFailed
		provider := p.Provider(delivery.Provider)
		if provider == nil {
			// The claim filters on registered providers; never let a
			// repository contract violation dead-letter the row.
			replayErr := permanentErr("unknown payment provider %q", delivery.Provider)
			outcome, replayErr = p.recordFailure(
				replayCtx,
				delivery.LogID,
				StatusFailed,
				replayErr.Error(),
				replayErr,
			)
			replayErrors = append(replayErrors, fmt.Errorf("replay webhook %d: %w", delivery.LogID, replayErr))
		} else {
			var replayErr error
			outcome, replayErr = p.dispatch(
				replayCtx,
				provider,
				delivery.LogID,
				delivery.EventType,
				delivery.RawBody,
				handler,
				true,
				failureStatus,
			)
			if replayErr != nil {
				replayErrors = append(replayErrors, fmt.Errorf("replay webhook %d: %w", delivery.LogID, replayErr))
			}
		}
		p.recordWebhookMetrics(
			replayCtx,
			delivery.Provider,
			delivery.EventType,
			webhookModeReplay,
			outcome,
			time.Since(started),
		)
		switch outcome {
		case webhookOutcomeProcessed:
			summary.Processed++
		case webhookOutcomeSkipped:
			summary.Skipped++
		case webhookOutcomeDeadLettered:
			summary.DeadLettered++
		default:
			summary.Failed++
		}
	}
	return summary, errors.Join(replayErrors...)
}

// dispatch runs the allowlist gate, parse, domain handler, and after-hook
// against an already-logged row (logID), updating its status as it goes.
// Shared by the first-delivery path and the failed-row reclaim path.
func (p *WebhookProcessor) dispatch(
	ctx context.Context,
	provider PaymentProvider,
	logID int64,
	eventType string,
	body []byte,
	handler PaymentEventHandler,
	replayMode bool,
	failureStatus string,
) (string, error) {
	// (4.5) Per-event-type allowlist (v0.5.1-E). Skipping happens AFTER
	// the log row is written so operators can see in payment_webhook_log
	// which events were rejected at the gate vs which never arrived.
	// nil map = allow everything (v0.5.0 behavior).
	if p.AllowedEventTypes != nil && !p.AllowedEventTypes[eventType] {
		if err := p.setStatus(ctx, logID, StatusSkipped, "event type not in allowlist"); err != nil {
			return webhookOutcomeFailed, err
		}
		return webhookOutcomeSkipped, nil
	}

	// (5) Parse + dispatch. Errors here flip the row to 'F' and bubble
	// up so the provider can retry — but only the parse/handle step is
	// retryable, never verify (a real attacker can't get past it) and
	// never log (idempotency rejects a re-attempt).
	event, err := provider.Parse(body)
	if err != nil {
		// Parse failures are permanent: the same payload won't
		// suddenly become parseable on retry.
		processErr := permanentErr("parse event: %v", err)
		return p.recordFailure(ctx, logID, failureStatus, err.Error(), processErr)
	}
	if event == nil {
		if err := p.setStatus(ctx, logID, StatusProcessed, ""); err != nil {
			return webhookOutcomeFailed, err
		}
		return webhookOutcomeProcessed, nil
	}
	event.Provider = provider.Name()
	event.RequestID = common.RequestIDFromContext(ctx)
	event.ReplayMode = replayMode
	if enricher, ok := provider.(PaymentEventEnricher); ok {
		if err := enricher.EnrichPaymentEvent(ctx, event); err != nil {
			processErr := fmt.Errorf("enrich event: %w", err)
			return p.recordFailure(ctx, logID, failureStatus, err.Error(), processErr)
		}
	}

	if handler == nil {
		processErr := fmt.Errorf("payment: event handler is not configured")
		return p.recordFailure(ctx, logID, failureStatus, processErr.Error(), processErr)
	}
	if err := handler.OnPaymentEvent(ctx, event); err != nil {
		processErr := fmt.Errorf("handle event: %w", err)
		return p.recordFailure(ctx, logID, failureStatus, err.Error(), processErr)
	}

	// (5.5) After-hook (v0.5.1-F). Cross-cutting follow-up — typically
	// an idempotent Stripe POST that finalizes setup-mode flow. Failure
	// flips the row to 'F' so the provider re-delivers; the hook MUST
	// be idempotent because OnPaymentEvent already ran successfully and
	// will run again on the retry.
	if p.AfterHandler != nil {
		if err := p.AfterHandler(ctx, event); err != nil {
			processErr := fmt.Errorf("after-handler: %w", err)
			return p.recordFailure(ctx, logID, failureStatus, err.Error(), processErr)
		}
	}

	if err := p.setStatus(ctx, logID, StatusProcessed, ""); err != nil {
		return webhookOutcomeFailed, err
	}
	return webhookOutcomeProcessed, nil
}

func (p *WebhookProcessor) recordFailure(
	ctx context.Context,
	logID int64,
	status string,
	message string,
	processErr error,
) (string, error) {
	if statusErr := p.setStatus(ctx, logID, status, message); statusErr != nil {
		return webhookOutcomeFailed, errors.Join(processErr, statusErr)
	}
	return outcomeForFailureStatus(status), processErr
}

func outcomeForFailureStatus(status string) string {
	if status == StatusDeadLetter {
		return webhookOutcomeDeadLettered
	}
	return webhookOutcomeFailed
}

func (p *WebhookProcessor) setStatus(ctx context.Context, logID int64, status string, message string) error {
	if err := p.Repo.UpdateStatus(ctx, logID, status, message); err != nil {
		statusErr := fmt.Errorf("payment: update webhook %d to status %s: %w", logID, status, err)
		p.logError(ctx, "%v", statusErr)
		return statusErr
	}
	return nil
}

func (p *WebhookProcessor) recordWebhookMetrics(
	ctx context.Context,
	provider string,
	eventType string,
	mode string,
	outcome string,
	duration time.Duration,
) {
	if p.Metrics == nil {
		return
	}
	if provider == "" {
		provider = "unknown"
	}
	if eventType == "" {
		eventType = "unknown"
	}
	labels := map[string]string{
		"provider":   provider,
		"event_type": eventType,
		"mode":       mode,
		"outcome":    outcome,
	}
	counterErr := p.Metrics.RecordMetric(ctx, port.MetricMeasurement{
		Name:   webhookMetricTotal,
		Help:   "Payment webhook lifecycle outcomes.",
		Kind:   port.MetricCounter,
		Value:  1,
		Labels: labels,
	})
	durationErr := p.Metrics.RecordMetric(ctx, port.MetricMeasurement{
		Name:   webhookMetricDuration,
		Help:   "Payment webhook lifecycle duration in seconds.",
		Kind:   port.MetricHistogram,
		Value:  port.DurationSeconds(duration),
		Labels: labels,
	})
	if err := errors.Join(counterErr, durationErr); err != nil {
		p.logError(ctx, "payment metrics: %v", err)
	}
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

func (p *WebhookProcessor) logError(ctx context.Context, format string, args ...any) {
	if p.Journal != nil {
		message := fmt.Sprintf(format, args...)
		if requestID := common.RequestIDFromContext(ctx); requestID != "" {
			message = fmt.Sprintf("request_id=%s %s", requestID, message)
		}
		p.Journal.Error(message)
	}
}
