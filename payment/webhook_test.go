package payment

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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
	processed map[string]bool // key = provider|eventID
}

type memRow struct {
	ID        int64
	Provider  string
	EventID   string
	EventType string
	Status    string
	Message   string
}

func newMemRepo() *memRepo {
	return &memRepo{
		logged:    map[string]bool{},
		processed: map[string]bool{},
	}
}

func (r *memRepo) Log(_ context.Context, provider, eventID, eventType string, _ []byte) (int64, error) {
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
	r.rows = append(r.rows, memRow{ID: id, Provider: provider, EventID: eventID, EventType: eventType, Status: StatusReceived})
	return id, nil
}

func (r *memRepo) Exists(_ context.Context, provider, eventID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.processed[provider+"|"+eventID], nil
}

func (r *memRepo) UpdateStatus(_ context.Context, logID int64, status, message string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.rows {
		if r.rows[i].ID == logID {
			r.rows[i].Status = status
			r.rows[i].Message = message
			if status == StatusProcessed {
				key := r.rows[i].Provider + "|" + r.rows[i].EventID
				r.processed[key] = true
			}
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

func (s *stubProvider) Name() string                                       { return s.name }
func (s *stubProvider) SignatureHeader() string                            { return s.sigHeader }
func (s *stubProvider) Verify(_ context.Context, _ string, _ []byte) error { return s.verifyErr }
func (s *stubProvider) Parse(_ []byte) (*PaymentEvent, error) {
	if s.parseErr != nil {
		return nil, s.parseErr
	}
	return s.event, nil
}

type recordingHandler struct {
	events []*PaymentEvent
	err    error
}

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
