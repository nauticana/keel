package realtime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/clock"
)

func TestTicketServiceSingleUse(t *testing.T) {
	now := clock.NewFake(time.Unix(1000, 0))
	mem := cache.NewMemoryCacheServiceWithClock(now)
	t.Cleanup(func() { _ = mem.Close() })
	s, ctx := &TicketService{Cache: mem}, context.Background()

	ticket, err := s.Mint(ctx, 7, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if id, err := s.Redeem(ctx, ticket, time.Minute); err == nil && id == 7 {
				wins.Add(1)
			} else if !errors.Is(err, ErrTicket) {
				t.Errorf("redeem: %v", err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("wins = %d, want 1", wins.Load())
	}

	expired, err := s.Mint(ctx, 7, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now.Advance(time.Minute)
	for _, bad := range []string{expired, "", strings.Repeat("z", 64)} {
		if _, err := s.Redeem(ctx, bad, time.Minute); !errors.Is(err, ErrTicket) {
			t.Fatalf("redeem %q: %v", bad, err)
		}
	}
	for _, zero := range []*TicketService{{}, s} {
		if _, err := zero.Mint(ctx, 0, time.Minute); err == nil {
			t.Fatal("minted without a user")
		}
	}
}
