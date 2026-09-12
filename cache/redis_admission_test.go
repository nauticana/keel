package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// redisAdmitter runs the real Lua script against an in-process Redis, so the
// all-or-nothing guarantee is tested where it actually lives.
func redisAdmitter(t *testing.T) (*CacheServiceImpl, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { client.Close() })
	return &CacheServiceImpl{client: client}, server
}

func TestRedisAdmit_ChargesEveryScope(t *testing.T) {
	c, server := redisAdmitter(t)

	res, err := c.Admit(context.Background(),
		AdmissionScope{Key: "{t}:tenant", Limit: 5, Window: time.Minute},
		AdmissionScope{Key: "{t}:fleet", Limit: 9, Window: time.Minute})
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if !res.Admitted || len(res.Counts) != 2 || res.Counts[0] != 1 || res.Counts[1] != 1 {
		t.Fatalf("res = %+v", res)
	}
	// The fixed window must be set on creation, or the counter never resets.
	if ttl := server.TTL("{t}:tenant"); ttl != time.Minute {
		t.Errorf("tenant TTL = %v, want 1m", ttl)
	}
}

func TestRedisAdmit_RejectionChargesNothing(t *testing.T) {
	c, _ := redisAdmitter(t)
	ctx := context.Background()
	narrow := AdmissionScope{Key: "{t}:tenant", Limit: 10, Window: time.Minute}
	wide := AdmissionScope{Key: "{t}:fleet", Limit: 1, Window: time.Minute}

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
	if res.RejectedKey != "{t}:fleet" {
		t.Errorf("RejectedKey = %q", res.RejectedKey)
	}
	if res.RetryAfter <= 0 || res.RetryAfter > time.Minute {
		t.Errorf("RetryAfter = %v, want the remaining window", res.RetryAfter)
	}
	if got, err := c.Get(ctx, "{t}:tenant"); err != nil || got != "1" {
		t.Errorf("tenant counter = %q (%v), want 1 — the rejected attempt must be free", got, err)
	}
}

func TestRedisAdmit_WindowExpiryResetsCounters(t *testing.T) {
	c, server := redisAdmitter(t)
	ctx := context.Background()
	scope := AdmissionScope{Key: "k", Limit: 1, Window: time.Minute}

	if res, _ := c.Admit(ctx, scope); !res.Admitted {
		t.Fatal("first admission rejected")
	}
	if res, _ := c.Admit(ctx, scope); res.Admitted {
		t.Fatal("second admission inside the window should be rejected")
	}
	server.FastForward(61 * time.Second)
	if res, _ := c.Admit(ctx, scope); !res.Admitted {
		t.Fatal("admission after the window expired should succeed")
	}
}

func TestRedisAdmit_CostIsChargedOnce(t *testing.T) {
	c, _ := redisAdmitter(t)
	ctx := context.Background()

	res, err := c.Admit(ctx, AdmissionScope{Key: "k", Limit: 10, Cost: 4, Window: time.Minute})
	if err != nil || !res.Admitted || res.Counts[0] != 4 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if res, _ := c.Admit(ctx, AdmissionScope{Key: "k", Limit: 10, Cost: 7, Window: time.Minute}); res.Admitted {
		t.Fatal("a charge crossing the limit must be rejected")
	}
	if got, _ := c.Get(ctx, "k"); got != "4" {
		t.Errorf("counter = %q, want 4", got)
	}
}

func TestRedisAdmit_EmptyAndInvalidScopes(t *testing.T) {
	c, _ := redisAdmitter(t)
	ctx := context.Background()

	if res, err := c.Admit(ctx); err != nil || !res.Admitted {
		t.Fatalf("no scopes = %+v, %v", res, err)
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
