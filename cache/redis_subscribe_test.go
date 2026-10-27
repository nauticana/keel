package cache

import (
	"strconv"
	"testing"
	"time"
)

func TestRedisSubscribeDropsWhenFull(t *testing.T) {
	c, _ := redisAdmitter(t)
	ctx := t.Context()
	ch, err := c.Subscribe(ctx, "topic")
	if err != nil {
		t.Fatal(err)
	}
	waitFor := func(cond func() bool) {
		for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("timed out")
			}
		}
	}
	// The subscription is live once a publish reaches it.
	waitFor(func() bool { n, _ := c.client.Publish(ctx, "topic", "probe").Result(); return n == 1 })
	for i := range 150 {
		if err := c.Publish(ctx, "topic", strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(func() bool { return len(ch) == cap(ch) })
	time.Sleep(100 * time.Millisecond) // let the overflow arrive and be dropped
	for len(ch) > 0 {
		<-ch
	}
	if err := c.Publish(ctx, "topic", "marker"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if got != "marker" {
			t.Errorf("next message = %q, want the overflow dropped", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the subscriber stalled")
	}
}
