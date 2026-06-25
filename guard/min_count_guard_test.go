package guard

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMinCountGuard_RejectsBelowMin(t *testing.T) {
	qs := fakeQuerier{rows: map[string][][]any{"qHist": {{int64(1)}}}}
	err := NewMinCountGuard("qHist", "query history", 2, time.Hour).Check(context.Background(), qs, baseInput())
	if !errors.Is(err, ErrGuardRejected) {
		t.Fatalf("want ErrGuardRejected, got %v", err)
	}
}

func TestMinCountGuard_PassesAtMin(t *testing.T) {
	qs := fakeQuerier{rows: map[string][][]any{"qHist": {{int64(2)}}}}
	if err := NewMinCountGuard("qHist", "query history", 2, time.Hour).Check(context.Background(), qs, baseInput()); err != nil {
		t.Fatalf("want pass at min, got %v", err)
	}
}

func TestMinCountGuard_NoRowsRejects(t *testing.T) {
	qs := fakeQuerier{rows: map[string][][]any{"qHist": nil}}
	if err := NewMinCountGuard("qHist", "query history", 1, time.Hour).Check(context.Background(), qs, baseInput()); !errors.Is(err, ErrGuardRejected) {
		t.Fatalf("want ErrGuardRejected on zero count, got %v", err)
	}
}
