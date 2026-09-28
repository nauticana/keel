package realtime

import (
	"context"
	"testing"

	"github.com/nauticana/keel/cache"
)

func TestUserDispatcher_DeliversNotificationFrame(t *testing.T) {
	c := cache.NewMemoryCacheService()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &Hub{Cache: c}
	if err := h.Run(ctx); err != nil {
		t.Fatal(err)
	}
	ws := dial(t, serve(t, h), 7, "")
	waitFor(t, func() bool { h.mu.RLock(); defer h.mu.RUnlock(); return len(h.users[7]) == 1 })

	d := &UserDispatcher{Cache: c}
	if err := d.DispatchTyped(ctx, 7, "order_shipped", "Order shipped", "Arrives Friday", map[string]string{"order": "9"}); err != nil {
		t.Fatal(err)
	}
	got := read(t, ws)
	if got["op"] != "notification" || got["type"] != "order_shipped" || got["title"] != "Order shipped" ||
		got["data"].(map[string]any)["order"] != "9" {
		t.Fatalf("frame = %v", got)
	}
	if err := d.Dispatch(ctx, 8, "offline", "", nil); err != nil {
		t.Fatalf("a user with no socket is not an error: %v", err)
	}
	if err := d.Send(ctx, "x", "t", "", nil); err == nil {
		t.Fatal("address delivery must fail")
	}
}
