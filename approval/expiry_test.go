package approval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExpiredRequestCannotBeDecided(t *testing.T) {
	ctx := context.Background()
	store := newStore()
	svc := &Service{DB: memRepo{store: store}}
	if _, err := svc.SubmitUntil(ctx, 1, "order", 10, 100, time.Now().Add(-time.Minute)); err == nil {
		t.Fatal("an expiry in the past must be refused")
	}
	req, err := svc.SubmitUntil(ctx, 1, "order", 10, 100, time.Now().Add(time.Hour))
	if err != nil || req.ExpiresAt.IsZero() || req.Expired {
		t.Fatalf("submit = %+v, %v", req, err)
	}
	store.clock = 2 * time.Hour
	if _, err := svc.Decide(ctx, 1, req.ID, 200, true, ""); !errors.Is(err, ErrExpired) {
		t.Fatalf("decide after expiry: %v", err)
	}
	got, _ := svc.Get(ctx, 1, req.ID)
	if got.Status != StatusPending || !got.Expired {
		t.Fatalf("an undecidable request is reported expired: %+v", got)
	}

	// The expired request must not block a new one for the same record.
	next, err := svc.Submit(ctx, 1, "order", 10, 100)
	if err != nil || next.ID == req.ID {
		t.Fatalf("resubmit = %+v, %v", next, err)
	}
	if old, _ := svc.Get(ctx, 1, req.ID); old.Status != StatusExpired {
		t.Fatalf("the stale request = %+v", old)
	}
	if _, err := svc.Decide(ctx, 1, next.ID, 200, true, ""); err != nil {
		t.Fatalf("a request without expiry never expires: %v", err)
	}
}

func TestExpireDueClosesAndRecords(t *testing.T) {
	ctx := context.Background()
	store := newStore()
	svc := &Service{DB: memRepo{store: store}}
	due, _ := svc.SubmitUntil(ctx, 1, "order", 10, 100, time.Now().Add(time.Hour))
	later, _ := svc.SubmitUntil(ctx, 1, "order", 11, 100, time.Now().Add(48*time.Hour))
	open, _ := svc.Submit(ctx, 1, "order", 12, 100)
	store.clock = 2 * time.Hour

	n, err := svc.ExpireDue(ctx)
	if err != nil || n != 1 {
		t.Fatalf("ExpireDue = %d, %v", n, err)
	}
	if again, _ := svc.ExpireDue(ctx); again != 0 {
		t.Fatalf("second sweep closed %d", again)
	}
	for id, want := range map[int64]string{due.ID: StatusExpired, later.ID: StatusPending, open.ID: StatusPending} {
		if got, _ := svc.Get(ctx, 1, id); got.Status != want {
			t.Errorf("request %d = %s, want %s", id, got.Status, want)
		}
	}
	events, _ := svc.Events(ctx, 1, due.ID)
	last := events[len(events)-1]
	if last.EventType != EventExpired || last.ActorID != 0 {
		t.Fatalf("expiry event = %+v", last)
	}
	if _, err := svc.Decide(ctx, 1, due.ID, 200, true, ""); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("decide an expired request: %v", err)
	}
}

func TestWithdrawIsTheMakersOnly(t *testing.T) {
	ctx := context.Background()
	store := newStore()
	svc := &Service{DB: memRepo{store: store}}
	req, _ := svc.Submit(ctx, 1, "order", 10, 100)

	for _, actor := range []int64{200, 0} {
		if _, err := svc.Withdraw(ctx, 1, req.ID, actor, ""); !errors.Is(err, ErrNotMaker) {
			t.Fatalf("withdraw by %d: %v", actor, err)
		}
	}
	if _, err := svc.Withdraw(ctx, 2, req.ID, 100, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another partner: %v", err)
	}
	got, err := svc.Withdraw(ctx, 1, req.ID, 100, "no longer needed")
	if err != nil || got.Status != StatusWithdrawn || got.DecisionNote != "no longer needed" || got.CheckerID != 0 {
		t.Fatalf("withdraw = %+v, %v", got, err)
	}
	events, _ := svc.Events(ctx, 1, req.ID)
	if last := events[len(events)-1]; last.EventType != EventWithdrawn || last.ActorID != 100 {
		t.Fatalf("withdraw event = %+v", last)
	}
	for name, call := range map[string]func() error{
		"withdraw twice": func() error { _, err := svc.Withdraw(ctx, 1, req.ID, 100, ""); return err },
		"decide":         func() error { _, err := svc.Decide(ctx, 1, req.ID, 200, true, ""); return err },
	} {
		if err := call(); !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s after withdrawal: %v", name, err)
		}
	}
	if _, err := svc.Submit(ctx, 1, "order", 10, 100); err != nil {
		t.Fatalf("a withdrawn record can be submitted again: %v", err)
	}
}
