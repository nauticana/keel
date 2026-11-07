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
	return &Service{DB: memRepo{store: store}, Administrators: admins}, store
}

// admins is the Administrators resolver of the tests: two for the partner, one for the platform.
func admins(_ context.Context, partnerID int64) ([]int64, error) {
	if partnerID == 0 {
		return []int64{1}, nil
	}
	return []int64{maker, checker}, nil
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
	s, _ := newService()
	ctx := context.Background()
	req, _ := s.Submit(ctx, partner, "invoice", 42, maker)
	if _, err := s.Decide(ctx, partner, req.ID, maker, true, ""); !errors.Is(err, ErrSameActor) {
		t.Fatalf("self decision without a policy row: %v", err)
	}
	allowFor := func(objectType string) {
		t.Helper()
		if err := s.SetPolicy(ctx, Policy{PartnerID: partner, ObjectType: objectType, AllowSinglePerson: true, ChangedBy: maker}); err != nil {
			t.Fatal(err)
		}
		if err := s.ConfirmPolicy(ctx, partner, objectType, checker); err != nil {
			t.Fatal(err)
		}
	}
	allowFor("order")
	if _, err := s.Decide(ctx, partner, req.ID, maker, true, ""); !errors.Is(err, ErrSameActor) {
		t.Fatalf("a policy for another kind does not apply: %v", err)
	}
	allowFor("invoice")
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

func TestPolicyFallsBackToPlatform(t *testing.T) {
	s, _ := newService()
	ctx := context.Background()
	allows := func(want bool, why string) {
		t.Helper()
		if ok, err := s.AllowsSinglePerson(ctx, partner, "invoice"); err != nil || ok != want {
			t.Fatalf("%s: %v %v", why, ok, err)
		}
	}
	allows(false, "no row")
	if err := s.SetPolicy(ctx, Policy{ObjectType: "invoice", AllowSinglePerson: true, ChangedBy: 1}); err != nil {
		t.Fatalf("a platform with one administrator needs no confirmation: %v", err)
	}
	allows(true, "platform row")
	if err := s.SetPolicy(ctx, Policy{PartnerID: partner, ObjectType: "invoice", ChangedBy: maker}); err != nil {
		t.Fatalf("requiring separation needs no confirmation: %v", err)
	}
	allows(false, "partner row over platform row")
	if err := s.SetPolicy(ctx, Policy{PartnerID: partner, ObjectType: "invoice", AllowSinglePerson: true, ChangedBy: maker}); err != nil {
		t.Fatal(err)
	}
	allows(false, "a pending partner row neither allows nor falls back to the platform")
	if err := s.ConfirmPolicy(ctx, partner, "invoice", checker); err != nil {
		t.Fatal(err)
	}
	allows(true, "the confirmed partner row")
}

func TestPolicyConfirmationIsAnotherAdministratorsCall(t *testing.T) {
	s, store := newService()
	ctx := context.Background()
	if err := s.ConfirmPolicy(ctx, partner, "invoice", checker); !errors.Is(err, ErrNoPendingPolicy) {
		t.Fatalf("nothing pending: %v", err)
	}
	if err := s.SetPolicy(ctx, Policy{PartnerID: partner, ObjectType: "invoice", ChangedBy: 99}); !errors.Is(err, ErrNotAdministrator) {
		t.Fatalf("change by a non-administrator: %v", err)
	}
	if err := s.SetPolicy(ctx, Policy{PartnerID: partner, ObjectType: "invoice", AllowSinglePerson: true, ChangedBy: maker}); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmPolicy(ctx, partner, "invoice", maker); !errors.Is(err, ErrPolicyConfirmation) {
		t.Fatalf("self-confirmation: %v", err)
	}
	if err := s.ConfirmPolicy(ctx, partner, "invoice", 99); !errors.Is(err, ErrNotAdministrator) {
		t.Fatalf("confirmation by a non-administrator: %v", err)
	}
	if ok, _ := s.AllowsSinglePerson(ctx, partner, "invoice"); ok {
		t.Fatal("a refused confirmation must leave the change pending")
	}
	if err := s.SetPolicy(ctx, Policy{PartnerID: partner, ObjectType: "invoice", ChangedBy: checker}); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmPolicy(ctx, partner, "invoice", checker); !errors.Is(err, ErrNoPendingPolicy) {
		t.Fatalf("a later change withdraws the pending one: %v", err)
	}
	if len(store.policies) != 2 {
		t.Fatalf("policies = %v", store.policies)
	}
	s.Administrators = nil
	if err := s.SetPolicy(ctx, Policy{PartnerID: partner, ObjectType: "invoice", ChangedBy: maker}); !errors.Is(err, ErrNotAdministrator) {
		t.Fatalf("without a resolver: %v", err)
	}
}
