package limiter

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/model"
)

func TestLocalRateLimiterEnforcesPartnerAndFleet(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	l := &LocalRateLimiter{
		Lanes:       map[string]Lane{"turn": {Partner: RateLimit{PerSecond: 1, Burst: 2}, Fleet: RateLimit{PerSecond: 1, Burst: 3}}},
		MaxPartners: 4096, Clock: fake,
	}
	ctx := context.Background()
	for range 2 {
		if err := l.Allow(ctx, "turn", subject(1)); err != nil {
			t.Fatal(err)
		}
	}
	err := l.Allow(ctx, "turn", subject(1))
	var limit *LimitError
	if !errors.As(err, &limit) || !errors.Is(err, ErrRateLimited) || limit.Scope != "turn.partner" || limit.RetryAfter() <= 0 {
		t.Fatalf("partner denial = %v", err)
	}
	if got := limit.ErrorHeaders().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q", got)
	}
	if err := l.Allow(ctx, "turn", subject(2)); err != nil {
		t.Fatal(err)
	}
	if err = l.Allow(ctx, "turn", subject(3)); !errors.As(err, &limit) || limit.Scope != "turn.fleet" {
		t.Fatalf("fleet denial = %v", err)
	}
	fake.Advance(2 * time.Second)
	if err := l.Allow(ctx, "turn", subject(1)); err != nil {
		t.Fatalf("refill: %v", err)
	}
}

func TestLocalRateLimiterLanesAndValidation(t *testing.T) {
	l := &LocalRateLimiter{Lanes: map[string]Lane{"turn": {Partner: RateLimit{PerSecond: 1, Burst: 1}}, "tool": {}}, MaxPartners: 4096}
	ctx := context.Background()
	if err := l.Allow(ctx, "turn", subject(7)); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(ctx, "turn", subject(7)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("turn = %v", err)
	}
	if err := l.Allow(ctx, "tool", subject(7)); err != nil {
		t.Fatalf("unlimited lane = %v", err)
	}
	if err := l.Allow(ctx, "model", subject(7)); err == nil {
		t.Fatal("an unconfigured lane must fail closed")
	}
	if err := l.Allow(ctx, "turn", model.AdmissionSubject{}); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("subject = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := l.Allow(canceled, "turn", subject(1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
	partial := &LocalRateLimiter{Lanes: map[string]Lane{"turn": {Partner: RateLimit{PerSecond: 1}}}, MaxPartners: 1}
	if err := partial.Allow(ctx, "turn", subject(1)); err == nil {
		t.Fatal("partial rate configuration must fail")
	}
	infinite := &LocalRateLimiter{Lanes: map[string]Lane{"turn": {Partner: RateLimit{PerSecond: math.Inf(1), Burst: 1}}}, MaxPartners: 1}
	if err := infinite.Allow(ctx, "turn", subject(1)); err == nil {
		t.Fatal("infinite rate configuration must fail")
	}
}

func TestLocalRateLimiterCapAndSweep(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	l := &LocalRateLimiter{Lanes: map[string]Lane{"turn": {Partner: RateLimit{PerSecond: 100, Burst: 1}}}, MaxPartners: 2, Clock: fake}
	ctx := context.Background()
	for id := int64(1); id <= 2; id++ {
		if err := l.Allow(ctx, "turn", subject(id)); err != nil {
			t.Fatal(err)
		}
	}
	// Buckets are drained (burst 1), so the sweep cannot evict and the map refuses.
	if err := l.Allow(ctx, "turn", subject(3)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("capacity = %v", err)
	}
	fake.Advance(time.Second)
	if err := l.Allow(ctx, "turn", subject(3)); err != nil {
		t.Fatal(err)
	}
}

func TestBucketMath(t *testing.T) {
	now := time.Unix(0, 0)
	b := NewBucket(10, 5, now)
	if !b.Take(5) || b.Take(1) || b.Wait(1) != 100*time.Millisecond {
		t.Fatal("burst, empty and wait semantics")
	}
	b.Refill(now.Add(200 * time.Millisecond))
	if !b.Take(2) {
		t.Fatal("refill did not accumulate")
	}
	b.Refund(100)
	if !b.Full() || b.Burst() != 5 {
		t.Fatal("refund must clamp to burst")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for a non-positive rate")
		}
	}()
	NewBucket(0, 1, now)
}
