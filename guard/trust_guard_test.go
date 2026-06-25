package guard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
)

// fakeQuerier returns a canned QueryResult per query name.
type fakeQuerier struct {
	rows map[string][][]any
	err  error
}

func (f fakeQuerier) Query(_ context.Context, name string, _ ...any) (*model.QueryResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &model.QueryResult{Rows: f.rows[name]}, nil
}

func (f fakeQuerier) GenID() int64 { return 0 }

func baseInput() GuardInput {
	return GuardInput{PartnerID: 42, DedupKey: "p42|/x|TECH", Now: time.Unix(1_700_000_000, 0).UTC()}
}

func TestDuplicateGuard_ReturnsExistingID(t *testing.T) {
	qs := fakeQuerier{rows: map[string][][]any{"qDup": {{int64(999)}}}}
	err := NewDuplicateGuard("qDup", time.Minute).Check(context.Background(), qs, baseInput())

	var dup *DuplicateError
	if !errors.As(err, &dup) {
		t.Fatalf("want *DuplicateError, got %v", err)
	}
	if dup.ExistingID != 999 {
		t.Fatalf("want existing id 999, got %d", dup.ExistingID)
	}
	if !errors.Is(err, ErrDuplicateInFlight) {
		t.Fatalf("DuplicateError should unwrap to ErrDuplicateInFlight")
	}
}

func TestDuplicateGuard_PassesWhenNoMatch(t *testing.T) {
	qs := fakeQuerier{rows: map[string][][]any{"qDup": nil}}
	if err := NewDuplicateGuard("qDup", time.Minute).Check(context.Background(), qs, baseInput()); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
}

func TestMaxCountGuard_RejectsAtMax(t *testing.T) {
	qs := fakeQuerier{rows: map[string][][]any{"qCount": {{int64(5)}}}}
	err := NewMaxCountGuard("qCount", "rate limit", 5, 30*24*time.Hour).Check(context.Background(), qs, baseInput())
	if !errors.Is(err, ErrGuardRejected) {
		t.Fatalf("want ErrGuardRejected, got %v", err)
	}
}

func TestMaxCountGuard_PassesBelowMax(t *testing.T) {
	qs := fakeQuerier{rows: map[string][][]any{"qCount": {{int64(4)}}}}
	if err := NewMaxCountGuard("qCount", "rate limit", 5, time.Hour).Check(context.Background(), qs, baseInput()); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
}

func TestMinAgeGuard_RejectsTooNew(t *testing.T) {
	in := baseInput()
	created := in.Now.Add(-2 * time.Hour).Format(time.RFC3339)
	qs := fakeQuerier{rows: map[string][][]any{"qAge": {{created}}}}
	err := NewMinAgeGuard("qAge", 7*24*time.Hour).Check(context.Background(), qs, in)
	if !errors.Is(err, ErrGuardRejected) {
		t.Fatalf("want ErrGuardRejected, got %v", err)
	}
}

func TestMinAgeGuard_PassesOldEnough(t *testing.T) {
	in := baseInput()
	created := in.Now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	qs := fakeQuerier{rows: map[string][][]any{"qAge": {{created}}}}
	if err := NewMinAgeGuard("qAge", 7*24*time.Hour).Check(context.Background(), qs, in); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
}

func TestGuardChain_FailsFastInOrder(t *testing.T) {
	qs := fakeQuerier{rows: map[string][][]any{
		"qDup":   {{int64(7)}}, // would reject
		"qCount": {{int64(0)}}, // would pass
	}}
	chain := NewGuardChain(
		NewMaxCountGuard("qCount", "rate", 5, time.Hour),
		NewDuplicateGuard("qDup", time.Minute),
	)
	err := chain.Check(context.Background(), qs, baseInput())
	var dup *DuplicateError
	if !errors.As(err, &dup) {
		t.Fatalf("chain should surface the duplicate error, got %v", err)
	}
}

func TestGuardChain_EmptyPasses(t *testing.T) {
	if err := NewGuardChain().Check(context.Background(), fakeQuerier{}, baseInput()); err != nil {
		t.Fatalf("empty chain should pass, got %v", err)
	}
}

func TestGuard_InfraErrorPropagates(t *testing.T) {
	qs := fakeQuerier{err: errors.New("db down")}
	err := NewDuplicateGuard("qDup", time.Minute).Check(context.Background(), qs, baseInput())
	if err == nil || errors.Is(err, ErrGuardRejected) || errors.Is(err, ErrDuplicateInFlight) {
		t.Fatalf("infra error should propagate as a plain error, got %v", err)
	}
}
