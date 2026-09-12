package cache

import (
	"context"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
)

func admitter(t *testing.T) (*MemoryCacheService, *clock.Fake) {
	t.Helper()
	fake := clock.NewFake(time.Time{})
	c := NewMemoryCacheServiceWithClock(fake)
	t.Cleanup(func() { c.Close() })
	return c, fake
}

func TestAdmit_ChargesEveryScope(t *testing.T) {
	c, _ := admitter(t)
	scopes := []AdmissionScope{
		{Key: "tenant", Limit: 5, Window: time.Minute},
		{Key: "fleet", Limit: 9, Window: time.Minute},
	}

	res, err := c.Admit(context.Background(), scopes...)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if !res.Admitted {
		t.Fatal("first admission rejected")
	}
	if len(res.Counts) != 2 || res.Counts[0] != 1 || res.Counts[1] != 1 {
		t.Fatalf("counts = %v", res.Counts)
	}
}

// The reason the interface exists: a rejection by the second scope must leave
// the first uncharged, or concurrent callers see an inflated count and the
// wider scope over-admits.
func TestAdmit_RejectionChargesNothing(t *testing.T) {
	c, _ := admitter(t)
	ctx := context.Background()
	narrow := AdmissionScope{Key: "tenant", Limit: 10, Window: time.Minute}
	wide := AdmissionScope{Key: "fleet", Limit: 1, Window: time.Minute}

	if _, err := c.Admit(ctx, narrow, wide); err != nil {
		t.Fatal(err)
	}
	res, err := c.Admit(ctx, narrow, wide)
	if err != nil {
		t.Fatal(err)
	}
	if res.Admitted {
		t.Fatal("second admission should exceed the fleet limit")
	}
	if res.RejectedKey != "fleet" {
		t.Errorf("RejectedKey = %q, want fleet", res.RejectedKey)
	}
	if res.RetryAfter != time.Minute {
		t.Errorf("RetryAfter = %v, want the remaining window", res.RetryAfter)
	}

	// The tenant counter must still read 1 — the rejected attempt was free.
	got, err := c.Get(ctx, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if got != "1" {
		t.Errorf("tenant counter = %s, want 1 (the rejected attempt was charged)", got)
	}
}

func TestAdmit_WindowExpiryResetsCounters(t *testing.T) {
	c, fake := admitter(t)
	ctx := context.Background()
	scope := AdmissionScope{Key: "tenant", Limit: 1, Window: time.Minute}

	if res, _ := c.Admit(ctx, scope); !res.Admitted {
		t.Fatal("first admission rejected")
	}
	if res, _ := c.Admit(ctx, scope); res.Admitted {
		t.Fatal("second admission inside the window should be rejected")
	}
	fake.Advance(time.Minute + time.Second)
	if res, _ := c.Admit(ctx, scope); !res.Admitted {
		t.Fatal("admission after the window expired should succeed")
	}
}

func TestAdmit_CostAndEmptyScopes(t *testing.T) {
	c, _ := admitter(t)
	ctx := context.Background()

	if res, err := c.Admit(ctx); err != nil || !res.Admitted {
		t.Fatalf("no scopes = %v, %v", res, err)
	}
	res, err := c.Admit(ctx, AdmissionScope{Key: "k", Limit: 10, Cost: 4, Window: time.Minute})
	if err != nil || !res.Admitted || res.Counts[0] != 4 {
		t.Fatalf("cost charge = %v, %v", res, err)
	}
	if res, _ := c.Admit(ctx, AdmissionScope{Key: "k", Limit: 10, Cost: 7, Window: time.Minute}); res.Admitted {
		t.Fatal("a charge crossing the limit must be rejected")
	}
	if _, err := c.Admit(ctx, AdmissionScope{Limit: 1, Window: time.Minute}); err == nil {
		t.Error("expected an error for a scope with no key")
	}
	if _, err := c.Admit(ctx, AdmissionScope{Key: "k", Limit: 1}); err == nil {
		t.Error("expected an error for a non-positive window")
	}
	duplicate := AdmissionScope{Key: "same", Limit: 1, Window: time.Minute}
	if _, err := c.Admit(ctx, duplicate, duplicate); err == nil {
		t.Error("expected an error for a repeated key")
	}
}

func TestAdmit_RejectsMoreScopesThanMemoryCanRetain(t *testing.T) {
	c := boundedCache(t, 1)
	_, err := c.Admit(context.Background(),
		AdmissionScope{Key: "a", Limit: 1, Window: time.Minute},
		AdmissionScope{Key: "b", Limit: 1, Window: time.Minute})
	if err == nil {
		t.Fatal("expected capacity error")
	}
}

func TestMemoryCache_ExpiresAtWindowBoundary(t *testing.T) {
	c, fake := admitter(t)
	scope := AdmissionScope{Key: "k", Limit: 1, Window: time.Minute}
	if res, err := c.Admit(context.Background(), scope); err != nil || !res.Admitted {
		t.Fatalf("first admission = %+v, %v", res, err)
	}
	fake.Advance(time.Minute)
	if res, err := c.Admit(context.Background(), scope); err != nil || !res.Admitted {
		t.Fatalf("boundary admission = %+v, %v", res, err)
	}
}
