package approval

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/port"
)

const (
	partner = int64(7)
	maker   = int64(10)
	checker = int64(11)
)

func newService() (*Service, *memStore) {
	store := newStore()
	return &Service{DB: memRepo{store: store}}, store
}

func TestDecideRecordsBothActors(t *testing.T) {
	s, store := newService()
	ctx := context.Background()
	req, err := s.Submit(ctx, partner, "invoice", 42, maker)
	if err != nil {
		t.Fatal(err)
	}
	decided, err := s.Decide(ctx, partner, req.ID, checker, true, "ok")
	if err != nil {
		t.Fatal(err)
	}
	if decided.Status != StatusApproved || decided.MakerID != maker || decided.CheckerID != checker || decided.DecisionNote != "ok" {
		t.Fatalf("decided = %+v", decided)
	}
	events, err := s.Events(ctx, partner, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].EventType != EventSubmitted || events[0].ActorID != maker ||
		events[1].EventType != EventApproved || events[1].ActorID != checker {
		t.Fatalf("events = %+v", store.events)
	}
}

func TestMakerCannotDecideWithoutPolicy(t *testing.T) {
	s, store := newService()
	ctx := context.Background()
	req, _ := s.Submit(ctx, partner, "invoice", 42, maker)
	if _, err := s.Decide(ctx, partner, req.ID, maker, true, ""); !errors.Is(err, ErrSameActor) {
		t.Fatalf("self decision without a policy row: %v", err)
	}
	store.single[partner] = false
	if _, err := s.Decide(ctx, partner, req.ID, maker, true, ""); !errors.Is(err, ErrSameActor) {
		t.Fatalf("self decision with separation required: %v", err)
	}
	store.single[partner] = true
	decided, err := s.Decide(ctx, partner, req.ID, maker, false, "")
	if err != nil {
		t.Fatalf("single-person partner: %v", err)
	}
	if decided.Status != StatusRejected || decided.CheckerID != maker {
		t.Fatalf("decided = %+v", decided)
	}
}

func TestDecidedRequestIsFinal(t *testing.T) {
	s, _ := newService()
	ctx := context.Background()
	req, _ := s.Submit(ctx, partner, "invoice", 42, maker)
	if _, err := s.Decide(ctx, partner, req.ID, checker, false, "missing total"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(ctx, partner, req.ID, checker, true, ""); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("second decision: %v", err)
	}
}

func TestOneOpenRequestPerRecordAndResubmission(t *testing.T) {
	s, _ := newService()
	ctx := context.Background()
	first, _ := s.Submit(ctx, partner, "invoice", 42, maker)
	if _, err := s.Submit(ctx, partner, "invoice", 42, maker); !errors.Is(err, ErrAlreadyOpen) {
		t.Fatalf("second open request: %v", err)
	}
	if _, err := s.Submit(ctx, partner, "invoice", 43, maker); err != nil {
		t.Fatalf("another record: %v", err)
	}
	if _, err := s.Decide(ctx, partner, first.ID, checker, false, ""); err != nil {
		t.Fatal(err)
	}
	again, err := s.Submit(ctx, partner, "invoice", 42, maker)
	if err != nil {
		t.Fatalf("resubmission after rejection: %v", err)
	}
	latest, err := s.Latest(ctx, partner, "invoice", 42)
	if err != nil || latest.ID != again.ID || latest.Status != StatusPending {
		t.Fatalf("latest = %+v, %v", latest, err)
	}
	pending, _ := s.Pending(ctx, partner)
	if len(pending) != 2 {
		t.Fatalf("pending = %d, want 2", len(pending))
	}
}

func TestOtherPartnerCannotDecide(t *testing.T) {
	s, _ := newService()
	ctx := context.Background()
	req, _ := s.Submit(ctx, partner, "invoice", 42, maker)
	if _, err := s.Decide(ctx, partner+1, req.ID, checker, true, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-partner decision: %v", err)
	}
}

func TestOnDecidedFailureRollsBackDecision(t *testing.T) {
	s, store := newService()
	ctx := context.Background()
	req, _ := s.Submit(ctx, partner, "invoice", 42, maker)
	boom := errors.New("parent update failed")
	var seen *Request
	s.OnDecided = func(_ context.Context, _ port.TxQueryService, r *Request) error {
		seen = r
		return boom
	}
	if _, err := s.Decide(ctx, partner, req.ID, checker, true, ""); !errors.Is(err, boom) {
		t.Fatalf("decide: %v", err)
	}
	if seen == nil || seen.Status != StatusApproved || seen.CheckerID != checker {
		t.Fatalf("hook saw %+v", seen)
	}
	got, _ := s.Get(ctx, partner, req.ID)
	if got.Status != StatusPending || got.CheckerID != 0 || len(store.events) != 1 {
		t.Fatalf("after rollback: %+v, events %d", got, len(store.events))
	}
}

func TestSubmitValidatesInput(t *testing.T) {
	s, _ := newService()
	if _, err := s.Submit(context.Background(), partner, " ", 42, maker); err == nil {
		t.Fatal("blank object type accepted")
	}
}
