package cache

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
)

func boundedCache(t *testing.T, capacity int) *MemoryCacheService {
	t.Helper()
	c := NewMemoryCacheService()
	c.capacity = capacity
	t.Cleanup(func() { c.Close() })
	return c
}

func TestMemoryCache_EvictsLeastRecentlyUsed(t *testing.T) {
	c := boundedCache(t, 3)
	ctx := context.Background()

	for _, k := range []string{"a", "b", "c"} {
		if err := c.Set(ctx, k, k, 0); err != nil {
			t.Fatal(err)
		}
	}
	// Touch "a" so "b" becomes the least recent.
	if _, err := c.Get(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(ctx, "d", "d", 0); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Get(ctx, "b"); !errors.Is(err, ErrCacheMiss) {
		t.Errorf("b should have been evicted, got %v", err)
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, err := c.Get(ctx, k); err != nil {
			t.Errorf("%s should have survived: %v", k, err)
		}
	}
}

func TestMemoryCache_StaysWithinCapacityUnderKeyFlood(t *testing.T) {
	const capacity = 50
	c := boundedCache(t, capacity)
	ctx := context.Background()

	for i := range 500 {
		if err := c.Set(ctx, strconv.Itoa(i), "v", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	entries, ordered := len(c.kv), c.lru.Len()
	c.mu.Unlock()
	if entries != capacity || ordered != capacity {
		t.Fatalf("held %d keys / %d ordered, want %d", entries, ordered, capacity)
	}
}

func TestMemoryCache_ZeroCapacityIsUnbounded(t *testing.T) {
	c := boundedCache(t, 0)
	ctx := context.Background()
	for i := range 200 {
		if err := c.Set(ctx, strconv.Itoa(i), "v", 0); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	entries := len(c.kv)
	c.mu.Unlock()
	if entries != 200 {
		t.Fatalf("held %d keys, want all 200", entries)
	}
}

func TestMemoryCache_InjectedClockDrivesExpiry(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	c := NewMemoryCacheServiceWithClock(fake)
	defer c.Close()
	ctx := context.Background()

	if err := c.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatal(err)
	}
	fake.Advance(59 * time.Second)
	if _, err := c.Get(ctx, "k"); err != nil {
		t.Fatalf("expired early: %v", err)
	}
	fake.Advance(2 * time.Second)
	if _, err := c.Get(ctx, "k"); !errors.Is(err, ErrCacheMiss) {
		t.Errorf("want a miss past the TTL, got %v", err)
	}
}

func TestMemoryCache_SweepDropsExpiredNotLive(t *testing.T) {
	fake := clock.NewFake(time.Time{})
	c := NewMemoryCacheServiceWithClock(fake)
	defer c.Close()
	ctx := context.Background()

	if err := c.Set(ctx, "short", "v", time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(ctx, "long", "v", time.Hour); err != nil {
		t.Fatal(err)
	}
	fake.Advance(2 * time.Second)
	c.sweep()

	c.mu.Lock()
	_, shortHeld := c.kv["short"]
	_, longHeld := c.kv["long"]
	c.mu.Unlock()
	if shortHeld {
		t.Error("expired key survived the sweep")
	}
	if !longHeld {
		t.Error("live key was swept")
	}
}
