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

type fakeQS struct{ calls []qsCall }

func (f *fakeQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	f.calls = append(f.calls, qsCall{name, args})
	return &model.QueryResult{}, nil
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

type fakeTx struct{ fakeQS }

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

var (
	_ data.QueryService   = (*fakeQS)(nil)
	_ data.TxQueryService = (*fakeTx)(nil)
)

// row layout matches qPending: id, partner_id, aggregate_type, aggregate_id, event_type, payload, attempts
func pendingRow(attempts int64) []any {
	return []any{int64(7), int64(42), "business", "99", "profile.updated", `{"x":1}`, attempts}
}

func TestHandleJob_SuccessMarksDone(t *testing.T) {
	qs := &fakeQS{}
	d := &fakeDispatcher{}
	w := &Worker{Dispatcher: d}

	if err := w.HandleJob(context.Background(), nil, nil, nil, qs, 7, pendingRow(0)); err != nil {
		t.Fatalf("HandleJob: %v", err)
	}
	if len(d.got) != 1 || d.got[0].AggregateID != "99" {
		t.Fatalf("dispatch not called with the event: %+v", d.got)
	}
	if qs.ran(qDone) == nil {
		t.Fatal("event not marked done")
	}
	if qs.ran(qRetry) != nil || qs.ran(qFail) != nil {
		t.Fatal("retry/fail ran on success")
	}
}

func TestHandleJob_FailureRetriesWithBackoff(t *testing.T) {
	qs := &fakeQS{}
	w := &Worker{Dispatcher: &fakeDispatcher{err: errors.New("smtp down")}, MaxAttempts: 5}

	if err := w.HandleJob(context.Background(), nil, nil, nil, qs, 7, pendingRow(0)); err == nil {
		t.Fatal("expected an error so the tick re-polls")
	}
	c := qs.ran(qRetry)
	if c == nil {
		t.Fatal("not scheduled for retry")
	}
	if c.args[0] != 2 { // first failure → backoff 2^1 = 2s
		t.Fatalf("backoff = %v, want 2", c.args[0])
	}
	if qs.ran(qFail) != nil || qs.ran(qDone) != nil {
		t.Fatal("dead-lettered/done instead of retried")
	}
}

func TestHandleJob_DeadLettersAtMaxAttempts(t *testing.T) {
	qs := &fakeQS{}
	w := &Worker{Dispatcher: &fakeDispatcher{err: errors.New("permanent")}, MaxAttempts: 5}

	// attempts already 4 → this dispatch is the 5th → dead-letter, not retry.
	if err := w.HandleJob(context.Background(), nil, nil, nil, qs, 7, pendingRow(4)); err == nil {
		t.Fatal("expected an error")
	}
	if qs.ran(qFail) == nil {
		t.Fatal("not dead-lettered at max attempts")
	}
	if qs.ran(qRetry) != nil {
		t.Fatal("retried instead of dead-lettering")
	}
}

func TestEnqueueTx_NullsZeroPartnerAndEmptyPayload(t *testing.T) {
	tx := &fakeTx{}
	err := EnqueueTx(context.Background(), tx, Event{
		AggregateType: "business", AggregateID: "5", EventType: "claimed",
	})
	if err != nil {
		t.Fatalf("EnqueueTx: %v", err)
	}
	if len(tx.calls) != 1 || tx.calls[0].name != qInsert {
		t.Fatalf("insert not run: %+v", tx.calls)
	}
	args := tx.calls[0].args // id, partner_id, aggregate_type, aggregate_id, event_type, payload
	if args[0] != int64(99) {
		t.Errorf("id = %v, want GenID 99", args[0])
	}
	if args[1] != nil {
		t.Errorf("partner_id = %v, want NULL for zero", args[1])
	}
	if args[5] != nil {
		t.Errorf("payload = %v, want NULL for empty", args[5])
	}
}
