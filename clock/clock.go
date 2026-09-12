// Package clock is keel's injectable time. It covers waiting as well as reading:
// a service given only Now still needs a real second to pass in its tests.
// Production passes System; tests pass NewFake.
package clock

import (
	"context"
	"time"
)

type Clock interface {
	Now() time.Time
	Since(t time.Time) time.Duration
	NewTimer(d time.Duration) Timer
	// NewTicker panics on a non-positive d, like time.NewTicker.
	NewTicker(d time.Duration) Ticker
	// Sleep waits for d, returning ctx.Err() if the context ends first.
	Sleep(ctx context.Context, d time.Duration) error
}

// Timer fires once; C is buffered, matching time.Timer.
type Timer interface {
	C() <-chan time.Time
	Stop() bool                 // reports whether it stopped the timer before it fired
	Reset(d time.Duration) bool // reports whether the timer was still active
}

// Ticker fires until stopped; a tick sent while C is full is dropped.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}
