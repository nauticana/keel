package limiter

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// RateLimit configures one token bucket in calls per second; both zero disables it.
type RateLimit struct {
	PerSecond float64
	Burst     int
}

func (l RateLimit) enabled() bool { return l.PerSecond > 0 && l.Burst > 0 }

func (l RateLimit) valid() bool {
	return l.PerSecond == 0 && l.Burst == 0 || l.enabled() && !math.IsNaN(l.PerSecond) && !math.IsInf(l.PerSecond, 0)
}

// Lane is one admission concern: a per-partner rate and a fleet-wide rate.
type Lane struct {
	Partner RateLimit
	Fleet   RateLimit
}

const partnerSweepCooldown = 100 * time.Millisecond

// LocalRateLimiter enforces per-partner and fleet token buckets per lane inside one process.
type LocalRateLimiter struct {
	Lanes map[string]Lane
	// MaxPartners bounds the buckets kept per lane.
	MaxPartners int
	Clock       clock.Clock

	once  sync.Once
	lanes map[string]*laneState
}

var _ port.RateLimiter = (*LocalRateLimiter)(nil)

func (l *LocalRateLimiter) now() time.Time {
	if l.Clock == nil {
		return time.Now()
	}
	return l.Clock.Now()
}

func (l *LocalRateLimiter) init() error {
	if l.MaxPartners <= 0 {
		return fmt.Errorf("local rate limiter: max partners must be positive")
	}
	for name, lane := range l.Lanes {
		if !lane.Partner.valid() || !lane.Fleet.valid() {
			return fmt.Errorf("local rate limiter: lane %q needs positive rate and burst or neither", name)
		}
	}
	l.once.Do(func() {
		l.lanes = make(map[string]*laneState, len(l.Lanes))
		for name, lane := range l.Lanes {
			state := &laneState{name: name, partner: lane.Partner, max: l.MaxPartners}
			if lane.Fleet.enabled() {
				state.fleet = NewBucket(lane.Fleet.PerSecond, float64(lane.Fleet.Burst), l.now())
			}
			l.lanes[name] = state
		}
	})
	return nil
}

// Allow admits one call; an unconfigured lane fails closed.
func (l *LocalRateLimiter) Allow(ctx context.Context, lane string, subject model.AdmissionSubject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if subject.PartnerID <= 0 {
		return ErrInvalidSubject
	}
	if err := l.init(); err != nil {
		return err
	}
	state, ok := l.lanes[lane]
	if !ok {
		return fmt.Errorf("local rate limiter: unknown lane %q", lane)
	}
	return state.allow(subject.PartnerID, l.now())
}

type laneState struct {
	mu        sync.Mutex
	name      string
	partner   RateLimit
	fleet     *Bucket
	partners  map[int64]*Bucket
	max       int
	nextSweep time.Time
}

func (s *laneState) allow(partnerID int64, now time.Time) error {
	if !s.partner.enabled() && s.fleet == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var bucket *Bucket
	var stored bool
	if s.partner.enabled() {
		if s.partners == nil {
			s.partners = make(map[int64]*Bucket)
		}
		bucket, stored = s.partners[partnerID]
		if !stored {
			// A drained bucket is never evicted (a replacement would be full), so only full buckets are
			// swept and the map refuses beyond its cap.
			if len(s.partners) >= s.max && !now.Before(s.nextSweep) {
				s.sweep(now)
				s.nextSweep = now.Add(partnerSweepCooldown)
			}
			if len(s.partners) >= s.max {
				return &LimitError{Err: ErrRateLimited, Scope: s.name + ".capacity", After: partnerSweepCooldown}
			}
			bucket = NewBucket(s.partner.PerSecond, float64(s.partner.Burst), now)
		}
		bucket.Refill(now)
	}
	if s.fleet != nil {
		s.fleet.Refill(now)
	}
	if bucket != nil && bucket.Wait(1) > 0 {
		return &LimitError{Err: ErrRateLimited, Scope: s.name + ".partner", After: bucket.Wait(1)}
	}
	if s.fleet != nil && s.fleet.Wait(1) > 0 {
		return &LimitError{Err: ErrRateLimited, Scope: s.name + ".fleet", After: s.fleet.Wait(1)}
	}
	// Deduct both only after both can grant, so a denial leaks nothing.
	if bucket != nil {
		bucket.Take(1)
		if !stored {
			s.partners[partnerID] = bucket
		}
	}
	if s.fleet != nil {
		s.fleet.Take(1)
	}
	return nil
}

func (s *laneState) sweep(now time.Time) {
	for partnerID, b := range s.partners {
		if b.Refill(now); b.Full() {
			delete(s.partners, partnerID)
		}
	}
}
