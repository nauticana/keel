package erasure

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/port"
)

func claimed(t *testing.T, store *memStore, s *Service, userID int, attempts int64) (int64, []any) {
	t.Helper()
	plan, err := s.Request(context.Background(), userID, userID)
	if err != nil {
		t.Fatal(err)
	}
	id := plan.Request.ID
	store.requests[id][2], store.requests[id][5] = StatusActive, attempts
	store.leases[id] = 77
	return id, []any{id, int64(userID), attempts, int64(77)}
}

func newTestWorker(s *Service) *Worker {
	return &Worker{NewService: func(context.Context, port.DatabaseRepository) (*Service, error) { return s, nil }}
}

func TestWorkerOutcomes(t *testing.T) {
	ctx := context.Background()
	store, accounts := newMemStore(5, 6, 7, 8), &memAccounts{}
	activity := activityClassifier()
	s := newTestService(store, accounts, activity)
	w := newTestWorker(s)
	journal := &memJournal{}

	id, row := claimed(t, store, s, 5, 0)
	if err := w.HandleJob(ctx, journal, nil, nil, store, id, row); err != nil || store.requests[id][2] != StatusDone {
		t.Fatalf("done: %v %v", err, store.requests[id])
	}

	id, row = claimed(t, store, s, 6, 0)
	store.holds[50] = &holdRow{userID: 6, reason: "litigation"}
	if err := w.HandleJob(ctx, journal, nil, nil, store, id, row); err != nil || store.requests[id][2] != StatusHeld {
		t.Fatalf("held: %v %v", err, store.requests[id])
	}

	accounts.err = errors.New("database down")
	id, row = claimed(t, store, s, 7, 1)
	if err := w.HandleJob(ctx, journal, nil, nil, store, id, row); err != nil {
		t.Fatal(err)
	}
	if r := store.requests[id]; r[2] != StatusPending || r[5] != int64(2) || r[7] == nil {
		t.Fatalf("retried with the error recorded: %v", r)
	}

	id, row = claimed(t, store, s, 8, maxAttempts-1)
	if err := w.HandleJob(ctx, journal, nil, nil, store, id, row); err != nil || store.requests[id][2] != StatusFailed {
		t.Fatalf("failed after the retry budget: %v %v", err, store.requests[id])
	}
}

func TestWorkerLostLease(t *testing.T) {
	store := newMemStore(5)
	s := newTestService(store, &memAccounts{})
	id, row := claimed(t, store, s, 5, 0)
	row[3] = int64(12)
	journal := &memJournal{}
	if err := newTestWorker(s).HandleJob(context.Background(), journal, nil, nil, store, id, row); err != nil {
		t.Fatal(err)
	}
	if store.requests[id][2] != StatusActive || len(journal.lines) != 1 {
		t.Errorf("a stale lease must not record the outcome: %v %v", store.requests[id], journal.lines)
	}
}

func TestWorkerQueriesExist(t *testing.T) {
	w := &Worker{}
	pending, claim, reclaim, _ := w.QueueQueries()
	for _, q := range []string{pending, claim, reclaim, qWorkerDone, qWorkerHeld, qWorkerRetry, qWorkerFail} {
		if w.GetOLTPQueries()[q] == "" {
			t.Errorf("query %s missing from the worker catalog", q)
		}
	}
	if _, err := w.erasure(context.Background(), nil); err == nil {
		t.Error("a worker without NewService must fail loudly")
	}
}
