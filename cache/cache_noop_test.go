package cache

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestNoOpCache_GetReturnsMissSentinel locks the contract that
// every consumer of port.CacheService relies on: a cold key returns
// the typed sentinel, not (("", nil)). Switching to ("", nil) would
// silently turn cache-miss branches into cache-hit-with-empty-string
// branches across the codebase.
func TestNoOpCache_GetReturnsMissSentinel(t *testing.T) {
	c := &NoOpCacheService{}
	v, err := c.Get(context.Background(), "any")
	if !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expected ErrCacheMiss, got %v", err)
	}
	if v != "" {
		t.Fatalf("expected empty value, got %q", v)
	}
}

// TestNoOpCache_MutatorsSucceed walks every mutator. Each must be a
// silent no-op — neither logging an error nor returning one — so a
// service initialized without a real cache backend keeps the same
// hot-path code structure as one that has Redis wired in.
func TestNoOpCache_MutatorsSucceed(t *testing.T) {
	c := &NoOpCacheService{}
	ctx := context.Background()

	cases := []struct {
		name string
		do   func() error
	}{
		{"Set", func() error { return c.Set(ctx, "k", "v", time.Second) }},
		{"Delete", func() error { return c.Delete(ctx, "k") }},
		{"Increment", func() error { _, err := c.Increment(ctx, "k"); return err }},
		{"RPush", func() error { return c.RPush(ctx, "list", "v") }},
		{"LPopAll", func() error { _, err := c.LPopAll(ctx, "list"); return err }},
		{"Publish", func() error { return c.Publish(ctx, "ch", "msg") }},
		{"Close", func() error { return c.Close() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.do(); err != nil {
				t.Fatalf("%s: NoOp must never error; got %v", tc.name, err)
			}
		})
	}
}

// TestNoOpCache_Increment_ReturnsZero locks Increment's specific
// contract — return 0, nil. A naive implementation that returns the
// per-call counter (1, 2, ...) would make NoOp behave differently
// from "no real cache", which leaks through to consumers that
// check counters as quotas.
func TestNoOpCache_Increment_ReturnsZero(t *testing.T) {
	c := &NoOpCacheService{}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		v, err := c.Increment(ctx, "k")
		if err != nil {
			t.Fatalf("Increment: %v", err)
		}
		if v != 0 {
			t.Fatalf("Increment must return 0; got %d on call %d", v, i)
		}
	}
}

// TestNoOpCache_LPopAll_ReturnsEmpty locks LPopAll's contract: empty
// list, no error. A nil-ne-empty distinction here matters because
// some consumers iterate the result without a nil-check.
func TestNoOpCache_LPopAll_ReturnsEmpty(t *testing.T) {
	c := &NoOpCacheService{}
	got, err := c.LPopAll(context.Background(), "k")
	if err != nil {
		t.Fatalf("LPopAll: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %d items", len(got))
	}
}

// TestNoOpCache_Subscribe_StaysOpenUntilContextCancels validates
// the Subscribe channel-lifecycle contract documented on the impl
// (cache_noop.go): the returned channel must NOT close immediately,
// because consumers can't tell that apart from a healthy disconnect
// from a real backend. It must close when ctx cancels.
func TestNoOpCache_Subscribe_StaysOpenUntilContextCancels(t *testing.T) {
	c := &NoOpCacheService{}
	ctx, cancel := context.WithCancel(context.Background())

	ch, err := c.Subscribe(ctx, "topic")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Channel must NOT be closed yet. We probe with a non-blocking
	// receive: a closed channel yields the zero value with ok=false
	// immediately; an open empty channel yields nothing on the
	// default case.
	select {
	case _, ok := <-ch:
		if !ok {
			t.Fatal("Subscribe channel closed before ctx cancelled")
		}
		t.Fatal("Subscribe channel produced a message on a no-op cache")
	default:
		// expected
	}

	cancel()

	// Now the channel must close. Wait with a timeout so a wedged
	// goroutine doesn't hang the test forever.
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel close after ctx cancelled, got message")
		}
	case <-time.After(time.Second):
		t.Fatal("Subscribe channel did not close within 1s of ctx cancel")
	}
}
