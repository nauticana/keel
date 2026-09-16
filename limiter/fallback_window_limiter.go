package limiter

import (
	"math"
	"sync"
	"time"
)

// fallbackWindowLimiter preserves the distributed limiter's fixed-window
// semantics while the shared store is unavailable. It is deliberately local:
// each replica receives only its configured fraction of a window's quota.
type fallbackWindowLimiter struct {
	lanes       map[string]*fallbackWindowLane
	maxPartners int
}

type fallbackWindowLane struct {
	mu       sync.Mutex
	partner  WindowLimit
	fleet    WindowLimit
	partners map[int64]windowCounter
	fleetUse windowCounter
}

type windowCounter struct {
	epoch int64
	used  int64
}

func reducedWindowLimit(limit WindowLimit, fraction float64) WindowLimit {
	if !limit.enabled() {
		return WindowLimit{}
	}
	scaled := float64(limit.Limit) * fraction
	if scaled >= float64(limit.Limit) {
		return limit
	}
	return WindowLimit{Limit: max(1, int64(math.Ceil(scaled))), Window: limit.Window}
}

func (l *fallbackWindowLimiter) allow(lane string, partnerID int64, now time.Time) error {
	state := l.lanes[lane]
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	var partner windowCounter
	if state.partner.enabled() {
		epoch := epochOf(now, state.partner.Window)
		if state.partners == nil {
			state.partners = make(map[int64]windowCounter)
		}
		var exists bool
		partner, exists = state.partners[partnerID]
		if exists && partner.epoch != epoch {
			delete(state.partners, partnerID)
			exists = false
		}
		if !exists {
			if len(state.partners) >= l.maxPartners {
				for id, counter := range state.partners {
					if counter.epoch != epoch {
						delete(state.partners, id)
					}
				}
			}
			if len(state.partners) >= l.maxPartners {
				return &LimitError{Err: ErrRateLimited, Scope: lane + ".capacity", After: untilNextWindow(now, state.partner.Window)}
			}
			partner = windowCounter{epoch: epoch}
		}
		if partner.used >= state.partner.Limit {
			return &LimitError{Err: ErrRateLimited, Scope: lane + ".partner", After: untilNextWindow(now, state.partner.Window)}
		}
	}

	if state.fleet.enabled() {
		epoch := epochOf(now, state.fleet.Window)
		if state.fleetUse.epoch != epoch {
			state.fleetUse = windowCounter{epoch: epoch}
		}
		if state.fleetUse.used >= state.fleet.Limit {
			return &LimitError{Err: ErrRateLimited, Scope: lane + ".fleet", After: untilNextWindow(now, state.fleet.Window)}
		}
	}

	if state.partner.enabled() {
		partner.used++
		state.partners[partnerID] = partner
	}
	if state.fleet.enabled() {
		state.fleetUse.used++
	}
	return nil
}

func untilNextWindow(now time.Time, window time.Duration) time.Duration {
	epoch := epochOf(now, window)
	return time.Duration((epoch+1)*int64(window) - now.UnixNano())
}
