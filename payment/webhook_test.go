package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// memRepo is an in-memory port.WebhookRepository for tests.
//
// Log enforces a unique index on (provider, event_id) — the second
// concurrent insert for the same key returns a pgconn.PgError with
// SQLSTATE 23505, mirroring what the real pgsql repo returns. Without
// this the concurrency test (P2-31) couldn't exercise the unique-
// violation race-guard branch in WebhookProcessor.Process.
type memRepo struct {
	mu        sync.Mutex
	rows      []memRow
	logged    map[string]bool // (provider, event_id) — set once Log succeeds
	updateErr error
	clock     time.Time // fake DB clock driving the claim lease
	lease     time.Duration
}

type memRow struct {
	ID             int64
	Provider       string
	EventID        string
	EventType      string
	RequestID      string
	RawBody        []byte
	Status         string
	Message        string
	ReplayAttempts int
	ReceivedAt     time.Time
	LastClaimedAt  time.Time
}

func newMemRepo() *memRepo {
	return &memRepo{
		logged: map[string]bool{},
		clock:  time.Unix(1_700_000_000, 0),
		lease:  900 * time.Second,
	}
}

func (r *memRepo) advance(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clock = r.clock.Add(d)
}

// pastLease mirrors the SQL `< CURRENT_TIMESTAMP - make_interval(...)`.
func (r *memRepo) pastLease(t time.Time) bool {
	return !t.IsZero() && r.clock.Sub(t) > r.lease
}

// claimable mirrors the SQL claim predicate: F past its cooldown, or an
// abandoned R past its lease.
func (r *memRepo) claimable(row *memRow) bool {
	if !row.LastClaimedAt.IsZero() && !r.pastLease(row.LastClaimedAt) {
		return false
	}
	return row.Status == StatusFailed ||
		(row.Status == StatusReceived && r.pastLease(coalesce(row.LastClaimedAt, row.ReceivedAt)))
}

func (r *memRepo) Log(_ context.Context, provider, eventID, eventType, requestID string, rawBody []byte) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := provider + "|" + eventID
	if r.logged[key] {
		// Mirror the SQLSTATE 23505 unique-violation that the real
		// pgsql repo returns when (provider, event_id) collides.
		// WebhookProcessor.Process detects this via isUniqueViolation
		// and treats it as "already-seen" — the charge-twice race
		// guard validated in TestProcess_ConcurrentDeliveriesChargeOnce.
		return 0, &pgconn.PgError{Code: "23505", Message: "duplicate key (provider, event_id)"}
	}
	r.logged[key] = true
	id := int64(len(r.rows) + 1)
	r.rows = append(r.rows, memRow{
		ID: id, Provider: provider, EventID: eventID, EventType: eventType,
		RequestID: requestID, RawBody: append([]byte(nil), rawBody...), Status: StatusReceived,
		ReceivedAt: r.clock,
	})
	return id, nil
}

// Exists mirrors the SQL repo: true once a row has been logged for
// (provider, eventID), regardless of its terminal status. (The previous
// "processed-only" double diverged from production and hid KR-002.)
func (r *memRepo) Exists(_ context.Context, provider, eventID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.logged[provider+"|"+eventID], nil
}

// ReclaimFailed mirrors SQLWebhookRepository: atomically claim a failed or
// lease-expired received row back to R and renew the lease; ok=false otherwise.
func (r *memRepo) ReclaimFailed(_ context.Context, provider, eventID string) (int64, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.rows {
		row := &r.rows[i]
		if row.Provider != provider || row.EventID != eventID {
			continue
		}
		abandoned := row.Status == StatusReceived && r.pastLease(coalesce(row.LastClaimedAt, row.ReceivedAt))
		if row.Status != StatusFailed && !abandoned {
			continue
		}
		row.Status = StatusReceived
		row.Message = ""
		row.LastClaimedAt = r.clock
		return row.ID, true, nil
	}
	return 0, false, nil
}

func coalesce(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	return a
}

func (r *memRepo) ClaimFailed(_ context.Context, maxAttempts int, afterID int64, providers []string) (*WebhookDelivery, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.rows {
		row := &r.rows[i]
		if row.ID <= afterID || !slices.Contains(providers, row.Provider) || !r.claimable(row) {
			continue
		}
		row.LastClaimedAt = r.clock
		if row.ReplayAttempts >= maxAttempts {
			row.Status = StatusDeadLetter
			return &WebhookDelivery{
				LogID: row.ID, Provider: row.Provider, EventID: row.EventID,
				EventType: row.EventType, RequestID: row.RequestID,
				RawBody: append([]byte(nil), row.RawBody...), ReplayAttempts: row.ReplayAttempts,
				DeadLettered: true,
			}, true, nil
		}
		row.Status = StatusReceived
		row.Message = ""
		row.ReplayAttempts++
		return &WebhookDelivery{
			LogID:          row.ID,
			Provider:       row.Provider,
			EventID:        row.EventID,
			EventType:      row.EventType,
			RequestID:      row.RequestID,
			RawBody:        append([]byte(nil), row.RawBody...),
			ReplayAttempts: row.ReplayAttempts,
		}, true, nil
	}
	return nil, false, nil
}

func (r *memRepo) UpdateStatus(_ context.Context, logID int64, status, message string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.updateErr != nil {
		return r.updateErr
	}
	for i := range r.rows {
		if r.rows[i].ID == logID {
			r.rows[i].Status = status
			r.rows[i].Message = message
			return nil
		}
	}
	return fmt.Errorf("row %d not found", logID)
}

func (r *memRepo) statusOf(logID int64) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.ID == logID {
			return row.Status
		}
	}
	return ""
}

// alwaysGoodProvider signs nothing and always parses successfully.
type stubProvider struct {
	name      string
	sigHeader string
	verifyErr error
	parseErr  error
	event     *PaymentEvent
}

type enrichingProvider struct {
	*stubProvider
	enrichErr error
	called    bool
}

func (p *enrichingProvider) EnrichPaymentEvent(_ context.Context, event *PaymentEvent) error {
	p.called = true
	if p.enrichErr != nil {
		return p.enrichErr
	}
	event.InvoiceLines = []InvoiceLine{{ProviderLineID: "il_complete"}}
	event.InvoiceLinesComplete = true
	return nil
}

func (s *stubProvider) Name() string                                       { return s.name }
func (s *stubProvider) SignatureHeader() string                            { return s.sigHeader }
func (s *stubProvider) Verify(_ context.Context, _ string, _ []byte) error { return s.verifyErr }
func (s *stubProvider) Parse(_ []byte) (*PaymentEvent, error) {
	if s.parseErr != nil {
		return nil, s.parseErr
	}
	return s.event, nil
}

// PeekEventMeta mirrors the Stripe-style peek used by every test fixture
// in this file — id + type from the top level of the JSON body. Returns
// empty strings (and no error) for a non-JSON body so the legacy
// "(no-id payload)" test cases keep their original error path.
func (s *stubProvider) PeekEventMeta(body []byte) (string, string, error) {
	var peek struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	if len(body) == 0 || body[0] != '{' {
		return "", "", nil
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return "", "", err
	}
	return peek.ID, peek.Type, nil
}

type recordingHandler struct {
	events []*PaymentEvent
	err    error
}

type recordedMetric struct {
	requestID   string
	measurement port.MetricMeasurement
}

type recordingMetrics struct {
	mu      sync.Mutex
	records []recordedMetric
}

func (m *recordingMetrics) RecordMetric(ctx context.Context, measurement port.MetricMeasurement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, recordedMetric{
		requestID:   common.RequestIDFromContext(ctx),
		measurement: measurement,
	})
	return nil
}

var _ port.MetricsRecorder = (*recordingMetrics)(nil)

func (h *recordingHandler) OnPaymentEvent(_ context.Context, e *PaymentEvent) error {
	h.events = append(h.events, e)
	return h.err
}

// A Stripe-shaped body is needed so extractEventMeta picks up the event id.
const stripeBody = `{"id":"evt_123","type":"checkout.session.completed","data":{"object":{}}}`

func newProcessor(repo WebhookRepository, prov PaymentProvider) *WebhookProcessor {
	return NewWebhookProcessor(repo, nil, prov)
}

func TestProcess_HappyPath(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov)

	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(handler.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(handler.events))
	}
	if got := repo.statusOf(1); got != StatusProcessed {
		t.Fatalf("expected status=P, got %q", got)
	}
}

func TestProcess_EnrichesBeforeHandler(t *testing.T) {
	repo := newMemRepo()
	prov := &enrichingProvider{stubProvider: &stubProvider{
		name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123", InvoiceID: "in_1"},
	}}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov)

	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler); err != nil {
		t.Fatal(err)
	}
	if !prov.called || len(handler.events) != 1 || !handler.events[0].InvoiceLinesComplete {
		t.Fatalf("called=%v events=%d event=%+v", prov.called, len(handler.events), handler.events)
	}
}

func TestProcess_EnrichmentFailureIsRetryable(t *testing.T) {
	repo := newMemRepo()
	prov := &enrichingProvider{
		stubProvider: &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123", InvoiceID: "in_1"}},
		enrichErr:    errors.New("stripe unavailable"),
	}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov)

	err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler)
	if err == nil || !strings.Contains(err.Error(), "enrich event") {
		t.Fatalf("err=%v", err)
	}
	if len(handler.events) != 0 || repo.statusOf(1) != StatusFailed {
		t.Fatalf("events=%d status=%q", len(handler.events), repo.statusOf(1))
	}
}

func TestProcess_Idempotent(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov)

	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Second call with the same event id must short-circuit on the
	// Exists check — handler runs exactly once and we never even Log a
	// second row (the previous "log then mark Duplicate" pattern was
	// the audit-poisoning vector P0-22 / P0-23 fixed).
	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(handler.events) != 1 {
		t.Fatalf("expected handler to be called once, got %d", len(handler.events))
	}
	if got := len(repo.rows); got != 1 {
		t.Fatalf("expected exactly 1 row in repo (no duplicate insert), got %d", got)
	}
	if got := repo.statusOf(1); got != StatusProcessed {
		t.Fatalf("expected first row status=P, got %q", got)
	}
}

func TestProcess_SignatureFails(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", verifyErr: errors.New("bad sig")}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov)

	err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler)
	if err == nil {
		t.Fatal("expected error from bad signature")
	}
	if len(handler.events) != 0 {
		t.Fatal("handler must not be invoked when signature fails")
	}
	// Verify-before-log: the repository must NOT have recorded an
	// unsigned request. Otherwise an attacker could fill the audit
	// table with arbitrary 256 KiB blobs by hammering the endpoint
	// with garbage. (P0-22.)
	if got := len(repo.rows); got != 0 {
		t.Fatalf("expected 0 rows on signature failure, got %d", got)
	}
}

// Empty event ids are refused before any DB write — the synthetic-id
// fallback that previously masked this is gone. (P0-24.)
func TestProcess_RejectsEmptyEventID(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{}}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov)

	body := []byte(`{"type":"checkout.session.completed","data":{"object":{}}}`) // no id
	err := p.Process(context.Background(), "stripe", "sig", body, handler)
	if err == nil {
		t.Fatal("expected error for missing event id")
	}
	if len(handler.events) != 0 {
		t.Fatal("handler must not run for an unidentified event")
	}
	if got := len(repo.rows); got != 0 {
		t.Fatalf("expected 0 rows for empty event id, got %d", got)
	}
}

func TestProcess_HandlerFails(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	handler := &recordingHandler{err: errors.New("domain error")}
	p := newProcessor(repo, prov)

	err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := repo.statusOf(1); got != StatusFailed {
		t.Fatalf("expected status=F, got %q", got)
	}
}

func TestProcess_StatusWriteFailureIsSurfaced(t *testing.T) {
	repo := newMemRepo()
	repo.updateErr = errors.New("database write failed")
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	p := newProcessor(repo, prov)

	err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), &recordingHandler{})
	if err == nil || !strings.Contains(err.Error(), "update webhook") {
		t.Fatalf("err = %v, want surfaced status-write failure", err)
	}
	if got := repo.statusOf(1); got != StatusReceived {
		t.Fatalf("status = %q, false processed acknowledgement", got)
	}
}

// TestProcess_RetriesAfterTransientFailure is the KR-002 regression: a
// delivery whose handler fails transiently (status F) must be re-claimed
// and re-run on the provider's next retry, not swallowed as "already
// seen". Without the reclaim path the row stays F forever and the event
// (subscription activation, invoice reconciliation, ...) is stranded.
func TestProcess_RetriesAfterTransientFailure(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	p := newProcessor(repo, prov)

	failing := &recordingHandler{err: errors.New("transient downstream error")}
	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), failing); err == nil {
		t.Fatal("expected first delivery to fail")
	}
	if got := repo.statusOf(1); got != StatusFailed {
		t.Fatalf("expected status=F after transient failure, got %q", got)
	}

	ok := &recordingHandler{}
	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), ok); err != nil {
		t.Fatalf("retry returned %v, want success", err)
	}
	if len(ok.events) != 1 {
		t.Fatalf("expected handler re-run once on retry, got %d", len(ok.events))
	}
	if got := repo.statusOf(1); got != StatusProcessed {
		t.Fatalf("expected status=P after successful retry, got %q", got)
	}
	if got := len(repo.rows); got != 1 {
		t.Fatalf("expected exactly 1 row (reclaimed, not re-inserted), got %d", got)
	}
}

func TestProcess_PropagatesRequestIDAndRecordsMetrics(t *testing.T) {
	repo := newMemRepo()
	metrics := &recordingMetrics{}
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov)
	p.Metrics = metrics
	ctx := common.WithRequestID(context.Background(), "req-webhook-1")

	if err := p.Process(ctx, "stripe", "sig", []byte(stripeBody), handler); err != nil {
		t.Fatal(err)
	}
	if len(handler.events) != 1 || handler.events[0].RequestID != "req-webhook-1" {
		t.Fatalf("handler events = %+v, want correlated request id", handler.events)
	}
	if repo.rows[0].RequestID != "req-webhook-1" {
		t.Fatalf("stored request id = %q", repo.rows[0].RequestID)
	}
	if len(metrics.records) != 2 {
		t.Fatalf("metrics = %d, want counter + histogram", len(metrics.records))
	}
	for _, record := range metrics.records {
		if record.requestID != "req-webhook-1" {
			t.Errorf("metric request id = %q", record.requestID)
		}
		if got := record.measurement.Labels["outcome"]; got != webhookOutcomeProcessed {
			t.Errorf("metric outcome = %q", got)
		}
		if got := record.measurement.Labels["mode"]; got != webhookModeDelivery {
			t.Errorf("metric mode = %q", got)
		}
	}
}

func TestRetryFailed_ReplaysStoredDelivery(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	p := newProcessor(repo, prov)
	ctx := common.WithRequestID(context.Background(), "req-original")
	if err := p.Process(ctx, "stripe", "sig", []byte(stripeBody), &recordingHandler{err: errors.New("down")}); err == nil {
		t.Fatal("initial delivery must fail")
	}

	handler := &recordingHandler{}
	summary, err := p.RetryFailed(context.Background(), handler, WebhookReplayOptions{Limit: 10, MaxAttempts: 3})
	if err != nil {
		t.Fatalf("RetryFailed: %v", err)
	}
	if summary != (WebhookReplaySummary{Claimed: 1, Processed: 1}) {
		t.Fatalf("summary = %+v", summary)
	}
	if len(handler.events) != 1 {
		t.Fatalf("handler calls = %d", len(handler.events))
	}
	if !handler.events[0].ReplayMode || handler.events[0].RequestID != "req-original" {
		t.Fatalf("replayed event = %+v", handler.events[0])
	}
	if got := repo.statusOf(1); got != StatusProcessed {
		t.Fatalf("status = %q, want P", got)
	}
}

func TestRetryFailed_DeadLettersFinalAttempt(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	p := newProcessor(repo, prov)
	failing := &recordingHandler{err: errors.New("ledger unavailable")}
	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), failing); err == nil {
		t.Fatal("initial delivery must fail")
	}

	first, err := p.RetryFailed(context.Background(), failing, WebhookReplayOptions{Limit: 1, MaxAttempts: 2})
	if err == nil {
		t.Fatal("first replay failure must be surfaced")
	}
	if first.Failed != 1 || repo.statusOf(1) != StatusFailed {
		t.Fatalf("first summary=%+v status=%q", first, repo.statusOf(1))
	}

	repo.advance(16 * time.Minute)
	second, err := p.RetryFailed(context.Background(), failing, WebhookReplayOptions{Limit: 1, MaxAttempts: 2})
	if err == nil {
		t.Fatal("final replay failure must be surfaced")
	}
	if second.DeadLettered != 1 || repo.statusOf(1) != StatusDeadLetter {
		t.Fatalf("second summary=%+v status=%q", second, repo.statusOf(1))
	}

	repo.advance(16 * time.Minute)
	third, err := p.RetryFailed(context.Background(), failing, WebhookReplayOptions{Limit: 1, MaxAttempts: 2})
	if err != nil || third.Claimed != 0 {
		t.Fatalf("dead-letter must be terminal: summary=%+v err=%v", third, err)
	}
}

func TestRetryFailed_LeaseSpacesAttemptsAcrossSweeps(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	p := newProcessor(repo, prov)
	failing := &recordingHandler{err: errors.New("still down")}
	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), failing); err == nil {
		t.Fatal("initial delivery must fail")
	}

	if summary, _ := p.RetryFailed(context.Background(), failing, WebhookReplayOptions{Limit: 5, MaxAttempts: 5}); summary.Claimed != 1 {
		t.Fatalf("first sweep summary = %+v", summary)
	}
	// A second sweep inside the lease window — the overlapping-sweep case —
	// must not spend another attempt on the same row.
	summary, err := p.RetryFailed(context.Background(), failing, WebhookReplayOptions{Limit: 5, MaxAttempts: 5})
	if err != nil || summary.Claimed != 0 {
		t.Fatalf("in-lease sweep summary=%+v err=%v", summary, err)
	}
	if repo.rows[0].ReplayAttempts != 1 {
		t.Fatalf("attempts = %d, want 1", repo.rows[0].ReplayAttempts)
	}

	repo.advance(16 * time.Minute)
	if summary, _ := p.RetryFailed(context.Background(), failing, WebhookReplayOptions{Limit: 5, MaxAttempts: 5}); summary.Claimed != 1 {
		t.Fatalf("post-lease sweep summary = %+v", summary)
	}
	if repo.rows[0].ReplayAttempts != 2 {
		t.Fatalf("attempts = %d, want 2", repo.rows[0].ReplayAttempts)
	}
}

func TestRetryFailed_RecoversAbandonedClaim(t *testing.T) {
	repo := newMemRepo()
	repo.rows = append(repo.rows, memRow{
		ID: 1, Provider: "stripe", EventID: "evt_123", EventType: "invoice.paid",
		RawBody: []byte(stripeBody), Status: StatusReceived, ReceivedAt: repo.clock,
	})
	repo.logged["stripe|evt_123"] = true
	p := newProcessor(repo, &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}})
	handler := &recordingHandler{}

	if summary, _ := p.RetryFailed(context.Background(), handler, WebhookReplayOptions{Limit: 5, MaxAttempts: 5}); summary.Claimed != 0 {
		t.Fatalf("in-lease R row must not be claimed: %+v", summary)
	}

	repo.advance(16 * time.Minute)
	summary, err := p.RetryFailed(context.Background(), handler, WebhookReplayOptions{Limit: 5, MaxAttempts: 5})
	if err != nil {
		t.Fatal(err)
	}
	if summary != (WebhookReplaySummary{Claimed: 1, Processed: 1}) || repo.statusOf(1) != StatusProcessed {
		t.Fatalf("summary=%+v status=%q", summary, repo.statusOf(1))
	}
}

func TestProcess_RedeliveryReclaimsAbandonedClaim(t *testing.T) {
	repo := newMemRepo()
	repo.rows = append(repo.rows, memRow{
		ID: 1, Provider: "stripe", EventID: "evt_123", EventType: "invoice.paid",
		RawBody: []byte(stripeBody), Status: StatusReceived, ReceivedAt: repo.clock,
	})
	repo.logged["stripe|evt_123"] = true
	p := newProcessor(repo, &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}})
	handler := &recordingHandler{}

	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler); err != nil || len(handler.events) != 0 {
		t.Fatalf("in-lease R row must short-circuit as duplicate: err=%v dispatches=%d", err, len(handler.events))
	}

	repo.advance(16 * time.Minute)
	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler); err != nil {
		t.Fatal(err)
	}
	if len(handler.events) != 1 || repo.statusOf(1) != StatusProcessed {
		t.Fatalf("dispatches=%d status=%q", len(handler.events), repo.statusOf(1))
	}
}

func TestRetryFailed_ClaimsEachRowOncePerSweep(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	p := newProcessor(repo, prov)
	failing := &recordingHandler{err: errors.New("still down")}
	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), failing); err == nil {
		t.Fatal("initial delivery must fail")
	}

	summary, err := p.RetryFailed(context.Background(), failing, WebhookReplayOptions{Limit: 50, MaxAttempts: 5})
	if err == nil {
		t.Fatal("replay failure must be surfaced")
	}
	if summary != (WebhookReplaySummary{Claimed: 1, Failed: 1}) {
		t.Fatalf("summary = %+v, one sweep must not burn the attempt budget", summary)
	}
	if repo.statusOf(1) != StatusFailed || repo.rows[0].ReplayAttempts != 1 {
		t.Fatalf("status=%q attempts=%d, want F with a single attempt", repo.statusOf(1), repo.rows[0].ReplayAttempts)
	}
}

func TestRetryFailed_DeadLettersRowExhaustedByLoweredBudget(t *testing.T) {
	repo := newMemRepo()
	repo.rows = append(repo.rows, memRow{
		ID: 1, Provider: "stripe", EventID: "evt_123",
		EventType: "invoice.paid", RawBody: []byte(stripeBody),
		Status: StatusFailed, ReplayAttempts: 3,
	})
	repo.logged["stripe|evt_123"] = true
	p := newProcessor(repo, &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}})
	handler := &recordingHandler{}

	summary, err := p.RetryFailed(context.Background(), handler, WebhookReplayOptions{Limit: 1, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Claimed != 1 || summary.DeadLettered != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if len(handler.events) != 0 || repo.statusOf(1) != StatusDeadLetter {
		t.Fatalf("handler events=%d status=%q", len(handler.events), repo.statusOf(1))
	}
}

func TestRetryFailed_SkipsUnregisteredProviderRows(t *testing.T) {
	repo := newMemRepo()
	repo.rows = append(repo.rows,
		memRow{ID: 1, Provider: "paddle", EventID: "evt_p", EventType: "invoice.paid", RawBody: []byte(stripeBody), Status: StatusFailed},
		memRow{ID: 2, Provider: "stripe", EventID: "evt_123", EventType: "invoice.paid", RawBody: []byte(stripeBody), Status: StatusFailed},
	)
	p := newProcessor(repo, &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}})

	summary, err := p.RetryFailed(context.Background(), &recordingHandler{}, WebhookReplayOptions{Limit: 10, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	if summary != (WebhookReplaySummary{Claimed: 1, Processed: 1}) {
		t.Fatalf("summary = %+v", summary)
	}
	if repo.statusOf(1) != StatusFailed || repo.rows[0].ReplayAttempts != 0 {
		t.Fatalf("unregistered-provider row must stay untouched: status=%q attempts=%d", repo.statusOf(1), repo.rows[0].ReplayAttempts)
	}
}

func TestWebhookReplaySQLUsesAtomicClaimAndVisibleStatusWrites(t *testing.T) {
	claimSQL := webhookQueries[qClaimFailedWebhook]
	for _, required := range []string{
		"FOR UPDATE SKIP LOCKED",
		"provider = ANY(?)",
		"AND id > ?",
		"last_claimed_at IS NULL",
		"COALESCE(last_claimed_at, received_at) < CURRENT_TIMESTAMP - make_interval(secs => ?)",
		"ELSE webhook.replay_attempts + 1",
		"WHEN candidate.exhausted THEN 'L'",
	} {
		if !strings.Contains(claimSQL, required) {
			t.Errorf("claim query missing %q", required)
		}
	}
	reclaimSQL := webhookQueries[qReclaimFailedWebhook]
	for _, required := range []string{
		"last_claimed_at = CURRENT_TIMESTAMP",
		"COALESCE(last_claimed_at, received_at) < CURRENT_TIMESTAMP - make_interval(secs => ?)",
	} {
		if !strings.Contains(reclaimSQL, required) {
			t.Errorf("reclaim query missing %q", required)
		}
	}
	if !strings.Contains(webhookQueries[qUpdateWebhookStatus], "RETURNING id") {
		t.Fatal("status update must expose a zero-row write")
	}
}

func TestProcess_UnknownProvider(t *testing.T) {
	repo := newMemRepo()
	p := newProcessor(repo, &stubProvider{name: "stripe"})
	err := p.Process(context.Background(), "nope", "", []byte("{}"), &recordingHandler{})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

// countingHandler counts OnPaymentEvent invocations atomically. The
// concurrency test fans 64 goroutines into Process simultaneously,
// so a non-atomic counter would race the test itself (and the race
// detector would flag it before the assertion fired).
type countingHandler struct {
	calls int64
	pre   func() // optional: held under no lock, used to widen the race window
}

func (h *countingHandler) OnPaymentEvent(_ context.Context, _ *PaymentEvent) error {
	if h.pre != nil {
		h.pre()
	}
	atomic.AddInt64(&h.calls, 1)
	return nil
}

// TestProcess_ConcurrentDeliveriesChargeOnce exercises the unique-
// index race-guard branch (step 4 in WebhookProcessor.Process).
//
// Scenario: two webhook deliveries for the same event id arrive
// closely enough that both pass the Exists() short-circuit before
// either reaches the Log() write. The unique constraint on
// (provider, event_id) makes one of the inserts fail with SQLSTATE
// 23505; isUniqueViolation translates that into "already-seen" so
// Process returns nil and the handler runs exactly once.
//
// Why it matters: a real Stripe retry storm during a slow handler
// is the canonical charge-twice vector P0-23 closed. This test
// regression-locks the fix.
//
// Mechanics:
//   - 64 goroutines block on a start channel, then race into
//     Process. With the handler's small sleep, multiple goroutines
//     are guaranteed to clear Exists() before any one finishes the
//     handler and flips the row to StatusProcessed.
//   - All but one Log() call returns the simulated 23505. The
//     concurrent first-caller eventually finishes and updates
//     status; subsequent goroutines that arrive AFTER UpdateStatus
//     short-circuit on Exists() instead — both branches must yield
//     "handler ran exactly once, no error to caller".
func TestProcess_ConcurrentDeliveriesChargeOnce(t *testing.T) {
	const goroutines = 64

	repo := newMemRepo()
	handler := &countingHandler{
		pre: func() {
			// Widen the race window so multiple goroutines reliably
			// pass Exists() before any one finishes UpdateStatus.
			// Without this the very first goroutine often completes
			// the entire pipeline before the rest are scheduled,
			// collapsing the test to the cheap-path branch only.
			time.Sleep(2 * time.Millisecond)
		},
	}
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	p := newProcessor(repo, prov)

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			errs[idx] = p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d returned %v; the unique-violation race guard must swallow duplicates", i, err)
		}
	}
	if got := atomic.LoadInt64(&handler.calls); got != 1 {
		t.Fatalf("handler called %d times, want exactly 1 (charge-twice prevention)", got)
	}

	// Exactly one row, processed. The unique-violation branch never
	// inserts a row at all; the cheap-path branch never reaches Log.
	repo.mu.Lock()
	rowCount := len(repo.rows)
	processedCount := 0
	for _, row := range repo.rows {
		if row.Status == StatusProcessed {
			processedCount++
		}
	}
	repo.mu.Unlock()
	if rowCount != 1 {
		t.Fatalf("expected exactly 1 logged row, got %d", rowCount)
	}
	if processedCount != 1 {
		t.Fatalf("expected exactly 1 processed row, got %d", processedCount)
	}
}

// v0.5.1-E: AllowedEventTypes gates dispatch — events not in the set
// are skipped (status=S) and never reach the handler.
func TestProcess_AllowedEventTypes_Skips(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov).WithAllowedEventTypes("invoice.paid")

	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(handler.events) != 0 {
		t.Fatalf("expected handler skipped, got %d events", len(handler.events))
	}
	if got := repo.statusOf(1); got != StatusSkipped {
		t.Fatalf("expected status=S (skipped), got %q", got)
	}
}

// v0.5.1-E: nil AllowedEventTypes preserves v0.5.0 behavior — every
// signed event reaches the handler.
func TestProcess_NoAllowlist_AllowsAll(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov) // AllowedEventTypes nil

	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(handler.events) != 1 {
		t.Fatalf("expected handler called once, got %d", len(handler.events))
	}
}

// v0.5.1-F: AfterHandler runs after a successful OnPaymentEvent and
// can use typed PaymentEvent fields.
func TestProcess_AfterHandler_Fires(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123", SetupIntentID: "seti_xyz"}}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov)
	var afterCalled atomic.Int32
	var seenSetup string
	p.AfterHandler = func(_ context.Context, e *PaymentEvent) error {
		afterCalled.Add(1)
		seenSetup = e.SetupIntentID
		return nil
	}

	if err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if afterCalled.Load() != 1 {
		t.Fatalf("expected after-handler called once, got %d", afterCalled.Load())
	}
	if seenSetup != "seti_xyz" {
		t.Fatalf("after-handler got wrong event: setup=%q", seenSetup)
	}
	if got := repo.statusOf(1); got != StatusProcessed {
		t.Fatalf("expected status=P after success, got %q", got)
	}
}

// v0.5.1-F: AfterHandler error flips the row to F and bubbles up so
// the provider re-delivers. The hook must therefore be idempotent.
func TestProcess_AfterHandlerError_FailsRow(t *testing.T) {
	repo := newMemRepo()
	prov := &stubProvider{name: "stripe", event: &PaymentEvent{ProviderEventID: "evt_123"}}
	handler := &recordingHandler{}
	p := newProcessor(repo, prov)
	p.AfterHandler = func(_ context.Context, _ *PaymentEvent) error {
		return errors.New("attach failed")
	}

	err := p.Process(context.Background(), "stripe", "sig", []byte(stripeBody), handler)
	if err == nil {
		t.Fatal("expected after-handler error to bubble up")
	}
	if !contains(err.Error(), "after-handler") {
		t.Fatalf("expected after-handler in error, got %v", err)
	}
	if got := repo.statusOf(1); got != StatusFailed {
		t.Fatalf("expected status=F on after-handler error, got %q", got)
	}
}

// contains avoids pulling in strings.Contains to a test that already
// has a tight set of imports — keeps the diff minimal.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// silence the time/sync imports when only some subset of tests run.
var _ = time.Second
var _ = sync.Mutex{}
