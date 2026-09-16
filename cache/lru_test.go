package cache

import (
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
)

func TestLRU_EvictsLeastRecentAndExpires(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	c := NewLRU[string, int](2, fake)
	c.Set("a", 1, 0)
	c.Set("b", 2, time.Minute)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should be live")
	}
	c.Set("c", 3, 0) // b is now least recent → evicted
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted")
	}
	c.Set("d", 4, time.Second)
	fake.Advance(time.Second)
	if _, ok := c.Get("d"); ok {
		t.Fatal("d should have expired at the boundary")
	}
	if c.Len() != 1 {
		t.Fatalf("len = %d, want 1 (c)", c.Len())
	}
}

func TestLRU_SetReplacesInPlaceAndRefreshesTTL(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	c := NewLRU[string, int](1, fake)
	c.Set("k", 1, time.Second)
	fake.Advance(900 * time.Millisecond)
	c.Set("k", 2, time.Second)
	fake.Advance(500 * time.Millisecond)
	if v, ok := c.Get("k"); !ok || v != 2 {
		t.Fatalf("got %d,%v; want the replaced value still live", v, ok)
	}
}

func TestLRU_SweepDropsExpiredWithinBudget(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	c := NewLRU[int, int](10, fake)
	for i := range 10 {
		c.Set(i, i, time.Second)
	}
	fake.Advance(2 * time.Second)
	if scanned := c.Sweep(4); scanned != 4 {
		t.Fatalf("scanned %d, want the budget", scanned)
	}
	if c.Len() != 6 {
		t.Fatalf("len = %d, want 6 left for the next batch", c.Len())
	}
}

func TestLRU_SweepContinuesPastLiveTailEntries(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	c := NewLRU[string, int](4, fake)
	c.Set("live", 1, 0)
	c.Set("expired-a", 2, time.Second)
	c.Set("expired-b", 3, time.Second)
	fake.Advance(2 * time.Second)

	for range 3 {
		c.Sweep(1)
	}
	if c.Len() != 1 {
		t.Fatalf("len = %d, want only the live tail entry", c.Len())
	}
}

func TestShardedLRU_SweeperRunsOnTheClock(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	c := NewShardedLRU[int, int](4, 400, time.Minute, 100, fake) // headroom: maphash does not spread keys evenly
	defer c.Close()
	for i := range 40 {
		c.Set(i, i, time.Second)
	}
	fake.Advance(2 * time.Second)
	if c.Len() != 40 {
		t.Fatalf("len = %d before a tick, want unswept 40", c.Len())
	}
	fake.Advance(time.Minute)
	deadline := time.Now().Add(2 * time.Second)
	for c.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("len = %d after a tick, want 0", c.Len())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestShardedLRU_CloseIsIdempotent(t *testing.T) {
	c := NewShardedLRU[string, string](2, 4, time.Minute, 8, clock.NewFake(time.Time{}))
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLRU_RejectsBadCapacity(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for a non-positive capacity")
		}
	}()
	NewLRU[string, string](0, nil)
}
