package cache

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
)

type casBackend struct {
	name    string
	cache   CacheService
	get     func(key string) (string, error)
	advance func(d time.Duration)
}

func casBackends(t *testing.T) []casBackend {
	fake := clock.NewFake(time.Unix(1_700_000_000, 0))
	memory := NewMemoryCacheServiceWithClock(fake)
	t.Cleanup(func() { memory.Close() })
	redisCache, server := redisAdmitter(t)
	return []casBackend{
		{"memory", memory, func(k string) (string, error) { return memory.Get(context.Background(), k) }, fake.Advance},
		{"redis", redisCache, func(k string) (string, error) { return redisCache.Get(context.Background(), k) }, server.FastForward},
	}
}

func TestCompareAndSet(t *testing.T) {
	for _, b := range casBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			cas := func(expected, value string, ttl time.Duration) bool {
				t.Helper()
				ok, err := b.cache.CompareAndSet(ctx, "head", expected, value, ttl)
				if err != nil {
					t.Fatalf("CompareAndSet(%q, %q): %v", expected, value, err)
				}
				return ok
			}

			if cas("1:1", "1:2", 0) {
				t.Fatal("a missing key must only match the empty expectation")
			}
			if !cas("", "1:1", time.Minute) {
				t.Fatal("the first write to a missing key must succeed")
			}
			if cas("", "1:9", time.Minute) {
				t.Fatal("an existing key must not match the empty expectation")
			}
			if cas("0:9", "1:2", time.Minute) {
				t.Fatal("a stale expectation must be refused")
			}
			if !cas("1:1", "2:1", time.Minute) {
				t.Fatal("the current value must be replaced")
			}
			if got, _ := b.get("head"); got != "2:1" {
				t.Fatalf("value = %q, want 2:1", got)
			}

			b.advance(time.Minute)
			if _, err := b.get("head"); !errors.Is(err, ErrCacheMiss) {
				t.Fatalf("value after ttl: err = %v, want ErrCacheMiss", err)
			}
			if !cas("", "3:1", 0) {
				t.Fatal("an expired key must match the empty expectation")
			}
			b.advance(time.Hour)
			if got, _ := b.get("head"); got != "3:1" {
				t.Fatalf("a zero ttl must not expire, value = %q", got)
			}

			if _, err := b.cache.CompareAndSet(ctx, "head", "3:1", "4:1", -time.Second); !errors.Is(err, errNegativeTTL) {
				t.Fatalf("negative ttl: err = %v", err)
			}
			if got, _ := b.get("head"); got != "3:1" {
				t.Fatalf("a refused ttl must not write, value = %q", got)
			}
		})
	}
}

func TestCompareAndSet_OneRacerWins(t *testing.T) {
	for _, b := range casBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			var wins atomic.Int32
			var wg sync.WaitGroup
			for i := range 16 {
				wg.Go(func() {
					ok, err := b.cache.CompareAndSet(context.Background(), "race", "", strconv.Itoa(i), 0)
					if err != nil {
						t.Error(err)
					}
					if ok {
						wins.Add(1)
					}
				})
			}
			wg.Wait()
			if wins.Load() != 1 {
				t.Fatalf("%d racers won, want 1", wins.Load())
			}
		})
	}
}
