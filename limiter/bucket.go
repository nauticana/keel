package limiter

import (
	"math"
	"time"
)

// Bucket is a token bucket; the caller provides locking and the clock.
type Bucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

// NewBucket returns a full bucket refilling at ratePerSecond up to burst; both must be positive.
func NewBucket(ratePerSecond, burst float64, now time.Time) *Bucket {
	if ratePerSecond <= 0 || burst <= 0 || math.IsNaN(ratePerSecond) || math.IsNaN(burst) || math.IsInf(ratePerSecond, 0) || math.IsInf(burst, 0) {
		panic("limiter: bucket rate and burst must be positive")
	}
	return &Bucket{rate: ratePerSecond, burst: burst, tokens: burst, last: now}
}

// Refill advances the balance to now.
func (b *Bucket) Refill(now time.Time) {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+b.rate*elapsed.Seconds())
		b.last = now
	}
}

// Take consumes n tokens when the balance allows it.
func (b *Bucket) Take(n float64) bool {
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// Wait returns the delay until n tokens will have accumulated.
func (b *Bucket) Wait(n float64) time.Duration {
	if b.tokens >= n {
		return 0
	}
	return time.Duration(math.Ceil((n - b.tokens) / b.rate * float64(time.Second)))
}

// Refund returns unused tokens, clamped to the burst capacity.
func (b *Bucket) Refund(n float64) { b.tokens = min(b.burst, b.tokens+n) }

// Full reports whether the bucket is indistinguishable from a fresh one.
func (b *Bucket) Full() bool { return b.tokens >= b.burst }

func (b *Bucket) Burst() float64 { return b.burst }
