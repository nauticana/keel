package outbox

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
)

type qsCall struct {
	name string
	args []any
}

type fakeQS struct {
	rows  map[string][][]any
	calls []qsCall
}

func newFakeQS() *fakeQS { return &fakeQS{rows: map[string][][]any{}} }

func (f *fakeQS) returns(name string, rows [][]any) *fakeQS { f.rows[name] = rows; return f }

func (f *fakeQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	f.calls = append(f.calls, qsCall{name, args})
	return &model.QueryResult{Rows: f.rows[name]}, nil
}
func (f *fakeQS) GenID() int64 { return 1 }
func (f *fakeQS) ran(name string) *qsCall {
	for i := range f.calls {
		if f.calls[i].name == name {
			return &f.calls[i]
		}
	}
	return nil
}

type fakeTx struct{ *fakeQS }

func (f *fakeTx) Commit(context.Context) error   { return nil }
func (f *fakeTx) Rollback(context.Context) error { return nil }
func (f *fakeTx) GenID() int64                   { return 99 }

type fakeDispatcher struct {
	err error
	got []Event
}

func (d *fakeDispatcher) Dispatch(_ context.Context, e Event) error {
	d.got = append(d.got, e)
	return d.err
}

type fakeLogger struct{ warnings []string }

func (*fakeLogger) Initialize(string, string) error { return nil }
func (*fakeLogger) Close()                          {}
func (*fakeLogger) Access(string)                   {}
func (*fakeLogger) Info(string)                     {}
func (l *fakeLogger) Warning(s string)              { l.warnings = append(l.warnings, s) }
func (*fakeLogger) Error(string)                    {}
func (*fakeLogger) Fatal(string)                    {}

var (
	_ data.QueryService   = (*fakeQS)(nil)
	_ data.TxQueryService = (*fakeTx)(nil)
)

// claimRow is the claim's RETURNING row: id, partner_id, aggregate_type,
// aggregate_id, event_type, payload, attempts, lease_token.
func claimRow(partnerID any, attempts, token int64) []any {
	return []any{int64(7), partnerID, "business", "99", "profile.updated", `{"x":1}`, attempts, token}
}

func handle(w *Worker, qs *fakeQS, lg *fakeLogger, row []any) error {
	return w.HandleJob(context.Background(), lg, nil, nil, qs, 7, row)
}

// applied marks a transition query as having affected its row (RETURNING id),
// i.e. the lease was still owned.
func applied(qs *fakeQS, name string) *fakeQS { return qs.returns(name, [][]any{{int64(7)}}) }

func TestHandleJob_SuccessMarksDoneScopedByToken(t *testing.T) {
	qs := applied(newFakeQS(), qDone)
	d := &fakeDispatcher{}
	lg := &fakeLogger{}
	if err := handle(&Worker{Dispatcher: d}, qs, lg, claimRow(int64(42), 0, 555)); err != nil {
		t.Fatalf("HandleJob: %v", err)
	}
	if len(d.got) != 1 || d.got[0].Id != 7 || d.got[0].PartnerID != 42 {
		t.Fatalf("dispatch got %+v, want id=7 partner=42", d.got)
	}
	done := qs.ran(qDone)
	if done == nil {
		t.Fatal("event not marked done")
	}
	if done.args[0] != int64(7) || done.args[1] != int64(555) {
		t.Fatalf("done scoped by %v, want [id=7, token=555]", done.args)
	}
	if qs.ran(qRetry) != nil || qs.ran(qFail) != nil {
		t.Fatal("retry/fail ran on success")
	}
	if len(lg.warnings) != 0 {
		t.Fatalf("unexpected warning on success: %v", lg.warnings)
	}
}

func TestHandleJob_NullPartnerIsZero(t *testing.T) {
	qs := applied(newFakeQS(), qDone)
	d := &fakeDispatcher{}
	_ = handle(&Worker{Dispatcher: d}, qs, &fakeLogger{}, claimRow(nil, 0, 1))
	if len(d.got) != 1 || d.got[0].PartnerID != 0 {
		t.Fatalf("NULL partner_id must map to 0, got %+v", d.got)
	}
}

func TestHandleJob_RetryBeforeMaxScopedByToken(t *testing.T) {
	qs := applied(newFakeQS(), qRetry)
	w := &Worker{Dispatcher: &fakeDispatcher{err: errors.New("boom")}, MaxAttempts: 5}
	_ = handle(w, qs, &fakeLogger{}, claimRow(int64(42), 0, 555))

	c := qs.ran(qRetry)
	if c == nil {
		t.Fatal("not scheduled for retry")
	}
	if c.args[0] != 2 { // backoff, last_error, id, token
		t.Fatalf("backoff %v, want 2", c.args[0])
	}
	if c.args[2] != int64(7) || c.args[3] != int64(555) {
		t.Fatalf("retry not scoped by (id, token): %v", c.args)
	}
	if qs.ran(qFail) != nil || qs.ran(qDone) != nil {
		t.Fatal("dead-lettered/done instead of retried")
	}
}

func TestHandleJob_DeadLettersAtMax(t *testing.T) {
	qs := applied(newFakeQS(), qFail)
	w := &Worker{Dispatcher: &fakeDispatcher{err: errors.New("permanent")}, MaxAttempts: 5}
	_ = handle(w, qs, &fakeLogger{}, claimRow(int64(42), 4, 555))
	if qs.ran(qFail) == nil {
		t.Fatal("not dead-lettered at max attempts")
	}
	if qs.ran(qRetry) != nil {
		t.Fatal("retried instead of dead-lettering")
	}
}

// A zero-row completion (lease lost to a reclaim) must warn, not be logged as
// a successful done.
func TestHandleJob_LostLeaseWarnsNoFalseSuccess(t *testing.T) {
	qs := newFakeQS() // qDone returns no rows → lease lost
	lg := &fakeLogger{}
	if err := handle(&Worker{Dispatcher: &fakeDispatcher{}}, qs, lg, claimRow(int64(42), 0, 555)); err != nil {
		t.Fatalf("lost lease must not be an error: %v", err)
	}
	if qs.ran(qDone) == nil {
		t.Fatal("qDone not attempted")
	}
	if len(lg.warnings) == 0 {
		t.Fatal("lost lease must be warned, not silently treated as done")
	}
}

func TestEnqueueTx_NullsZeroPartnerAndEmptyPayload(t *testing.T) {
	tx := &fakeTx{fakeQS: newFakeQS()}
	if err := EnqueueTx(context.Background(), tx, Event{
		AggregateType: "business", AggregateID: "5", EventType: "claimed",
	}); err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}
	ins := tx.ran(qInsert)
	if ins == nil {
		t.Fatal("insert not run")
	}
	if ins.args[0] != int64(99) {
		t.Errorf("id = %v, want GenID 99", ins.args[0])
	}
	if ins.args[1] != nil {
		t.Errorf("partner_id = %v, want NULL for zero", ins.args[1])
	}
	if ins.args[5] != nil {
		t.Errorf("payload = %v, want NULL for empty", ins.args[5])
	}
}
