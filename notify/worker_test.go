package notify

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/worker"
)

func enqueued(t *testing.T, store *memStore, msg Message) {
	t.Helper()
	if _, err := newQueue(store).Enqueue(context.Background(), 7, "order", msg); err != nil {
		t.Fatal(err)
	}
}

// drain runs one leased JobLoop tick of w over store, as the worker runtime does.
func drain(w *Worker, store *memStore, lg *fakeLogger) {
	pending, claim, reclaim, name := w.QueueQueries()
	loop := &worker.JobLoop{QS: store, Journal: lg, GetPendingQuery: pending, ClaimQuery: claim, ReclaimQuery: reclaim, WorkerName: name, Leased: w.LeaseClaim()}
	loop.Reclaim(context.Background())
	loop.Run(context.Background(), func(ctx context.Context, jobID int64, row []any) error {
		return w.HandleJob(ctx, lg, nil, nil, store, jobID, row)
	})
}

func TestWorker_DeliversEachChannelOnce(t *testing.T) {
	store := newMemStore()
	enqueued(t, store, Message{PartnerID: 3, Title: "Shipped", Body: "b", Data: map[string]string{"order": "9"}})
	sender := &fakeSender{}
	w := &Worker{Sender: sender}
	drain(w, store, &fakeLogger{})
	drain(w, store, &fakeLogger{})
	if len(sender.got) != 2 {
		t.Fatalf("sent %d, want one per channel", len(sender.got))
	}
	req := sender.got[0]
	if req.UserID != 7 || req.PartnerID != 3 || req.Type != "order" || req.Title != "Shipped" || req.Body != "b" || req.Data["order"] != "9" {
		t.Fatalf("request = %+v", req)
	}
	if req.DedupeKey == "" || req.DedupeKey == sender.got[1].DedupeKey {
		t.Fatalf("dedupe keys must be per row: %q, %q", req.DedupeKey, sender.got[1].DedupeKey)
	}
	for _, r := range store.rows {
		if r.status != StatusSent || r.leaseToken != 0 {
			t.Fatalf("row %v status=%s token=%d, want sent and released", r.id, r.status, r.leaseToken)
		}
	}
}

func TestWorker_Outcomes(t *testing.T) {
	transient := errors.New("smtp: 421 try later")
	for _, tc := range []struct {
		name      string
		sendErr   error
		attempts  int64
		want      string
		wantDelay int
	}{
		{"duplicate is a prior delivery", fmt.Errorf("%w: k", port.ErrNotificationDuplicate), 0, StatusSent, 0},
		{"suppressed is terminal", &port.SuppressedError{Channel: "email", Reason: "bounce"}, 0, StatusSuppressed, 0},
		{"transient retries with backoff", transient, 2, StatusPending, 8},
		{"transient at the limit fails", transient, 4, StatusFailed, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			q := &Queue{DB: memRepo{store: store}, Channels: func(string) []string { return []string{"email"} }}
			if _, err := q.Enqueue(context.Background(), 7, "order", Message{Title: "x"}); err != nil {
				t.Fatal(err)
			}
			row := store.byChannel("email")
			row.attempts = tc.attempts
			lg := &fakeLogger{}
			drain(&Worker{Sender: &fakeSender{errs: map[string]error{"email": tc.sendErr}}}, store, lg)
			if row.status != tc.want || row.delay != tc.wantDelay || row.attempts != tc.attempts+1 {
				t.Fatalf("status=%s delay=%d attempts=%d, want %s/%d/%d", row.status, row.delay, row.attempts, tc.want, tc.wantDelay, tc.attempts+1)
			}
			if tc.want == StatusFailed && len(lg.errors) != 1 {
				t.Fatalf("a failed delivery must be logged as an error, got %v", lg.errors)
			}
		})
	}
}

func TestWorker_UndecodableDataFails(t *testing.T) {
	store := newMemStore()
	enqueued(t, store, Message{Title: "x"})
	store.byChannel("email").data = "{not json"
	sender := &fakeSender{}
	drain(&Worker{Sender: sender}, store, &fakeLogger{})
	if r := store.byChannel("email"); r.status != StatusFailed {
		t.Fatalf("status = %s, want failed", r.status)
	}
	if len(sender.got) != 1 || sender.got[0].Channel != "inbox" {
		t.Fatalf("only the decodable row may be sent, got %+v", sender.got)
	}
}

func TestWorker_LostLeaseLeavesNewerClaim(t *testing.T) {
	store := newMemStore()
	enqueued(t, store, Message{Title: "x"})
	row := store.byChannel("email")
	row.status, row.leaseToken = StatusActive, 999
	lg := &fakeLogger{}
	claim := []any{row.id, int64(7), nil, "order", "email", "x", "", nil, int64(0), int64(1)}
	if err := (&Worker{Sender: &fakeSender{}}).HandleJob(context.Background(), lg, nil, nil, store, row.id.(int64), claim); err != nil {
		t.Fatal(err)
	}
	if row.status != StatusActive || row.leaseToken != 999 || len(lg.warnings) != 1 {
		t.Fatalf("stale worker overwrote the claim: status=%s token=%d warnings=%v", row.status, row.leaseToken, lg.warnings)
	}
}

func TestWorker_OutcomeWriteErrorSurfaces(t *testing.T) {
	store := newMemStore()
	enqueued(t, store, Message{Title: "x"})
	store.failOn = qSent
	row := store.byChannel("email")
	claim := []any{row.id, int64(7), nil, "order", "email", "x", "", nil, int64(0), int64(1)}
	if err := (&Worker{Sender: &fakeSender{}}).HandleJob(context.Background(), &fakeLogger{}, nil, nil, store, row.id.(int64), claim); err == nil {
		t.Fatal("want the outcome write error")
	}
}

func TestWorker_RequiresSender(t *testing.T) {
	if err := (&Worker{}).HandleJob(context.Background(), &fakeLogger{}, nil, nil, newMemStore(), 1, nil); !errors.Is(err, ErrNoSender) {
		t.Fatalf("err = %v, want ErrNoSender", err)
	}
}

func TestWorker_Queries(t *testing.T) {
	w := &Worker{BatchLimit: 7}
	qs := w.GetOLTPQueries()
	pending, claim, reclaim, _ := w.QueueQueries()
	for _, name := range []string{pending, claim, reclaim, qSent, qSuppressed, qRetry, qFail} {
		if qs[name] == "" {
			t.Fatalf("query %s missing", name)
		}
	}
}

func TestBackoffSeconds(t *testing.T) {
	for attempt, want := range map[int]int{-3: 1, 0: 1, 1: 2, 3: 8, 11: 2048, 12: 3600, 1000: 3600} {
		if got := backoffSeconds(attempt); got != want {
			t.Fatalf("backoffSeconds(%d) = %d, want %d", attempt, got, want)
		}
	}
}
