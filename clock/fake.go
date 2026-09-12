package clock

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Fake is a Clock that only moves when Advance or Set is called, so a test
// drives timers and tickers deterministically instead of sleeping. Safe for
// concurrent use.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*fakeWaiter
}

var (
	_ Clock  = (*Fake)(nil)
	_ Timer  = (*fakeTimer)(nil)
	_ Ticker = (*fakeTicker)(nil)
)

// NewFake starts a fake clock at start; a zero start uses a fixed, non-zero
// instant so durations since "the beginning" stay meaningful.
func NewFake(start time.Time) *Fake {
	if start.IsZero() {
		start = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	}
	return &Fake{now: start}
}

type fakeWaiter struct {
	at     time.Time
	period time.Duration // >0 for a ticker
	ch     chan time.Time
	// stopped waiters are dropped at the next Set; queued tracks whether the
	// waiter is still in the clock's list, so Reset knows to re-register one
	// that already fired.
	stopped bool
	queued  bool
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) Since(t time.Time) time.Duration { return f.Now().Sub(t) }

// Advance moves the clock forward by d, firing everything due. A ticker crossed
// several times fires per elapsed period, coalescing as a real ticker does.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setLocked(f.now.Add(d))
}

// Set moves the clock to t. Moving backwards is allowed and fires nothing.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setLocked(t)
}

func (f *Fake) setLocked(t time.Time) {
	f.now = t
	due := make([]*fakeWaiter, 0, len(f.waiters))
	live := f.waiters[:0]
	for _, w := range f.waiters {
		if w.stopped {
			w.queued = false
			continue
		}
		if !w.at.After(t) {
			due = append(due, w)
			if w.period <= 0 {
				w.queued = false // one-shot: drop it
				continue
			}
		}
		live = append(live, w)
	}
	f.waiters = live
	// Fire in due order so two timers arrive in time order.
	sort.SliceStable(due, func(i, j int) bool { return due[i].at.Before(due[j].at) })
	for _, w := range due {
		if w.period > 0 {
			at := w.at
			remaining := t.Sub(w.at) % w.period
			w.at = t.Add(w.period - remaining)
			select {
			case w.ch <- at:
			default:
			}
			continue
		}
		select {
		case w.ch <- w.at:
		default:
		}
	}
}

func (f *Fake) NewTimer(d time.Duration) Timer {
	f.mu.Lock()
	w := &fakeWaiter{at: f.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		w.ch <- f.now
	} else {
		w.queued = true
		f.waiters = append(f.waiters, w)
	}
	f.mu.Unlock()
	return &fakeTimer{clock: f, w: w}
}

func (f *Fake) NewTicker(d time.Duration) Ticker {
	if d <= 0 {
		panic("clock: NewTicker requires a positive period")
	}
	f.mu.Lock()
	w := &fakeWaiter{at: f.now.Add(d), period: d, ch: make(chan time.Time, 1), queued: true}
	f.waiters = append(f.waiters, w)
	f.mu.Unlock()
	return &fakeTicker{clock: f, w: w}
}

func (f *Fake) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := f.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C():
		return nil
	}
}

type fakeTimer struct {
	clock *Fake
	w     *fakeWaiter
}

func (t *fakeTimer) C() <-chan time.Time { return t.w.ch }

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := !t.w.stopped && t.w.at.After(t.clock.now)
	t.w.stopped = true
	return active
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := !t.w.stopped && t.w.at.After(t.clock.now)
	if t.w.queued {
		for i, waiter := range t.clock.waiters {
			if waiter == t.w {
				t.clock.waiters = append(t.clock.waiters[:i], t.clock.waiters[i+1:]...)
				break
			}
		}
		t.w.queued = false
	}
	select {
	case <-t.w.ch:
	default:
	}
	t.w.at = t.clock.now.Add(d)
	t.w.stopped = false
	if d <= 0 {
		t.w.ch <- t.clock.now
	} else {
		t.w.queued = true
		t.clock.waiters = append(t.clock.waiters, t.w)
	}
	return active
}

type fakeTicker struct {
	clock *Fake
	w     *fakeWaiter
}

func (t *fakeTicker) C() <-chan time.Time { return t.w.ch }

func (t *fakeTicker) Stop() {
	t.clock.mu.Lock()
	t.w.stopped = true
	t.clock.mu.Unlock()
}
