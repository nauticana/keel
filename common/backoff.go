package common

import (
	"math"
	"math/rand/v2"
	"time"
)

// Backoff is capped exponential backoff with equal jitter: attempt n waits
// between half and all of Base·2^(n-1), never more than Max.
type Backoff struct {
	Base    time.Duration  // first delay; zero or less is one second
	Max     time.Duration  // cap; zero or less is uncapped
	Entropy func() float64 // in [0,1); nil is math/rand/v2
}

// Delay returns the wait before retry attempt (1-based; lower counts as 1).
func (b Backoff) Delay(attempt int) time.Duration {
	base := b.Base
	if base <= 0 {
		base = time.Second
	}
	limit := time.Duration(math.MaxInt64)
	if b.Max > 0 {
		limit = b.Max
	}
	d := min(base, limit)
	for i := 1; i < attempt && d < limit; i++ {
		if d > limit/2 {
			d = limit
			break
		}
		d *= 2
	}
	d = min(d, limit)
	entropy := rand.Float64
	if b.Entropy != nil {
		entropy = b.Entropy
	}
	random := entropy()
	if math.IsNaN(random) {
		random = 0
	}
	half := d / 2
	return half + time.Duration(min(max(random, 0), 1)*float64(d-half))
}

// Seconds is Delay in whole seconds, at least one, for a SQL interval.
func (b Backoff) Seconds(attempt int) int {
	return max(1, int(b.Delay(attempt)/time.Second))
}
