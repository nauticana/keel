package clock

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestFakeTimerFiresOnlyWhenAdvancedPast(t *testing.T) {
	c := NewFake(time.Time{})
	timer := c.NewTimer(time.Minute)

	c.Advance(59 * time.Second)
	select {
	case <-timer.C():
		t.Fatal("timer fired early")
	default:
	}

	c.Advance(time.Second)
	select {
	case at := <-timer.C():
		if got := at.Sub(c.Now()); got != 0 {
			t.Errorf("fired at %v, clock at %v", at, c.Now())
		}
	default:
		t.Fatal("timer did not fire")
	}
}

func TestFakeTimerResetAfterFiring(t *testing.T) {
	c := NewFake(time.Time{})
	timer := c.NewTimer(time.Second)
	c.Advance(time.Second)
	<-timer.C()

	if timer.Reset(time.Second) {
		t.Error("Reset reported an already-fired timer as active")
	}
	c.Advance(time.Second)
	select {
	case <-timer.C():
	default:
		t.Fatal("timer did not fire after Reset")
	}
}

func TestFakeTimerNonPositiveDurationFiresImmediately(t *testing.T) {
	c := NewFake(time.Time{})
	for _, d := range []time.Duration{0, -time.Second} {
		timer := c.NewTimer(d)
		select {
		case <-timer.C():
		default:
			t.Fatalf("timer with duration %v did not fire", d)
		}
	}
}

func TestFakeTimerResetDiscardsOldTick(t *testing.T) {
	c := NewFake(time.Time{})
	timer := c.NewTimer(time.Second)
	c.Advance(time.Second)
	timer.Reset(time.Minute)
	select {
	case <-timer.C():
		t.Fatal("Reset left the old tick queued")
	default:
	}
}

func TestFakeTickerRepeatsAndStops(t *testing.T) {
	c := NewFake(time.Time{})
	ticker := c.NewTicker(time.Second)

	for i := 0; i < 3; i++ {
		c.Advance(time.Second)
		select {
		case <-ticker.C():
		default:
			t.Fatalf("tick %d missing", i)
		}
	}

	ticker.Stop()
	c.Advance(time.Second)
	select {
	case <-ticker.C():
		t.Fatal("ticker fired after Stop")
	default:
	}
}

func TestFakeTickerCoalescesLargeAdvance(t *testing.T) {
	c := NewFake(time.Time{})
	ticker := c.NewTicker(time.Nanosecond)
	c.Advance(time.Hour)
	select {
	case <-ticker.C():
	default:
		t.Fatal("coalesced tick missing")
	}
	select {
	case <-ticker.C():
		t.Fatal("missed ticks were not coalesced")
	default:
	}
}

func TestFakeConcurrentAdvancesAreNotLost(t *testing.T) {
	c := NewFake(time.Time{})
	start := c.Now()
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Advance(time.Second)
		}()
	}
	wg.Wait()
	if got := c.Since(start); got != 100*time.Second {
		t.Fatalf("advanced %v, want 100s", got)
	}
}

func TestFakeStopPreventsFiring(t *testing.T) {
	c := NewFake(time.Time{})
	timer := c.NewTimer(time.Second)
	if !timer.Stop() {
		t.Error("Stop should report an active timer")
	}
	c.Advance(time.Second)
	select {
	case <-timer.C():
		t.Fatal("stopped timer fired")
	default:
	}
}

func TestFakeSleepHonoursContext(t *testing.T) {
	c := NewFake(time.Time{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Sleep(ctx, time.Hour) }()

	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Sleep ignored cancellation")
	}
}

func TestSystemSleepReturnsAfterDuration(t *testing.T) {
	if err := (System{}).Sleep(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("sleep: %v", err)
	}
}
