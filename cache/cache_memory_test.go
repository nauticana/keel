package cache

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemoryCache_SetGetRoundTrip(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx := context.Background()

	if err := c.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "v" {
		t.Fatalf("Get: %q want %q", got, "v")
	}
}

func TestMemoryCache_GetMiss(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()

	v, err := c.Get(context.Background(), "absent")
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("err = %v, want ErrCacheMiss", err)
	}
	if v != "" {
		t.Fatalf("value = %q, want empty", v)
	}
}

func TestMemoryCache_TTLExpiresLazily(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx := context.Background()

	if err := c.Set(ctx, "k", "v", 30*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := c.Get(ctx, "k"); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Get after TTL: err = %v, want ErrCacheMiss", err)
	}
}

func TestMemoryCache_SetWithoutTTLPersists(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx := context.Background()

	if err := c.Set(ctx, "k", "v", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	got, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "v" {
		t.Fatalf("Get = %q, want %q", got, "v")
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx := context.Background()

	_ = c.Set(ctx, "k", "v", time.Minute)
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, "k"); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Get after Delete: err = %v, want ErrCacheMiss", err)
	}
}

func TestMemoryCache_IncrementCreatesAtOne(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()

	n, err := c.Increment(context.Background(), "fresh")
	if err != nil {
		t.Fatalf("Increment: %v", err)
	}
	if n != 1 {
		t.Fatalf("Increment = %d, want 1", n)
	}
}

// TestMemoryCache_IncrementAtomicity is the critical property test
// for the rate-limit path. If Increment isn't atomic, attackers can
// race past the cap. 50 goroutines × 200 increments must yield
// exactly 10000.
func TestMemoryCache_IncrementAtomicity(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx := context.Background()

	var wg sync.WaitGroup
	const G, N = 50, 200
	for i := 0; i < G; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < N; j++ {
				_, _ = c.Increment(ctx, "ctr")
			}
		}()
	}
	wg.Wait()

	got, err := c.Get(ctx, "ctr")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "10000" {
		t.Fatalf("counter = %q, want %q", got, "10000")
	}
}

// TestMemoryCache_IncrementPreservesTTL guards the rate-limit window:
// once the caller has Set the TTL on the first increment, subsequent
// Increment calls must NOT reset it — otherwise an attacker pumping
// the contact every few seconds keeps pushing the window forward and
// effectively bypasses the cap.
func TestMemoryCache_IncrementPreservesTTL(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx := context.Background()

	_, _ = c.Increment(ctx, "rl")                  // creates "1", no expiry
	_ = c.Set(ctx, "rl", "1", 60*time.Millisecond) // caller pins TTL
	_, _ = c.Increment(ctx, "rl")                  // bumps to "2", expiry preserved
	_, _ = c.Increment(ctx, "rl")                  // bumps to "3"

	time.Sleep(80 * time.Millisecond)
	if _, err := c.Get(ctx, "rl"); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Get after TTL: err = %v, want ErrCacheMiss (Increment must not have reset TTL)", err)
	}
}

func TestMemoryCache_RPushLPopAllOrdering(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx := context.Background()

	for _, v := range []string{"a", "b", "c"} {
		if err := c.RPush(ctx, "q", v); err != nil {
			t.Fatalf("RPush %s: %v", v, err)
		}
	}
	got, err := c.LPopAll(ctx, "q")
	if err != nil {
		t.Fatalf("LPopAll: %v", err)
	}
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("LPopAll = %v, want [a b c]", got)
	}
	again, _ := c.LPopAll(ctx, "q")
	if len(again) != 0 {
		t.Fatalf("LPopAll second time = %v, want empty", again)
	}
}

func TestMemoryCache_PublishSubscribeFanOut(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a, err := c.Subscribe(ctx, "topic")
	if err != nil {
		t.Fatalf("Subscribe a: %v", err)
	}
	b, err := c.Subscribe(ctx, "topic")
	if err != nil {
		t.Fatalf("Subscribe b: %v", err)
	}

	if err := c.Publish(ctx, "topic", "hello"); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	for name, ch := range map[string]<-chan string{"a": a, "b": b} {
		select {
		case msg := <-ch:
			if msg != "hello" {
				t.Fatalf("subscriber %s got %q, want hello", name, msg)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %s timed out", name)
		}
	}
}

func TestMemoryCache_SubscribeClosesOnContextCancel(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())

	ch, err := c.Subscribe(ctx, "topic")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatalf("expected closed channel")
		}
	case <-time.After(time.Second):
		t.Fatalf("channel did not close after context cancel")
	}
}

func TestMemoryCache_CloseIsIdempotent(t *testing.T) {
	c := NewMemoryCacheService()
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestMemoryCache_SweeperDropsExpired ensures the background sweeper
// actually runs. We can't wait the default 60s in a unit test, so this
// test calls sweep() directly after expiry and confirms the entry is
// gone from the map.
func TestMemoryCache_SweeperDropsExpired(t *testing.T) {
	c := NewMemoryCacheService()
	defer c.Close()
	ctx := context.Background()

	_ = c.Set(ctx, "k", "v", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	c.sweep()

	c.mu.Lock()
	_, present := c.kv["k"]
	c.mu.Unlock()
	if present {
		t.Fatalf("expected sweep to drop expired key")
	}
}
