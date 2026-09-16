package limiter

import (
	"context"
	"fmt"
	"sync"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// FairSlotLimiter is a weighted semaphore with one FIFO per partner served round-robin, so no partner
// monopolizes capacity and a large request cannot starve behind small ones.
type FairSlotLimiter struct {
	Capacity int
	// MaxWaiters bounds queued acquisitions.
	MaxWaiters int

	mu       sync.Mutex
	inUse    int
	waiting  int
	partners map[int64]*slotQueue
	ready    []*slotQueue
}

var _ port.ConcurrencyLimiter = (*FairSlotLimiter)(nil)

type slotQueue struct {
	partner int64
	waiters []*slotWaiter
}

type slotWaiter struct {
	weight  int
	ready   chan struct{}
	granted bool
}

func (l *FairSlotLimiter) Acquire(ctx context.Context, subject model.AdmissionSubject) (port.ConcurrencyLease, error) {
	return l.AcquireWeighted(ctx, subject, 1)
}

func (l *FairSlotLimiter) AcquireWeighted(ctx context.Context, subject model.AdmissionSubject, weight int) (port.ConcurrencyLease, error) {
	if l.Capacity <= 0 || l.MaxWaiters <= 0 {
		return nil, fmt.Errorf("fair slot limiter: capacity and max waiters must be positive")
	}
	if subject.PartnerID <= 0 || weight <= 0 {
		return nil, ErrInvalidSubject
	}
	if weight > l.Capacity {
		return nil, fmt.Errorf("%w: weight %d exceeds capacity %d", ErrInvalidSubject, weight, l.Capacity)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	waiter := &slotWaiter{weight: weight, ready: make(chan struct{})}
	l.mu.Lock()
	if l.partners == nil {
		l.partners = make(map[int64]*slotQueue)
	}
	if l.waiting >= l.MaxWaiters {
		l.mu.Unlock()
		return nil, fmt.Errorf("%w: concurrency queue capacity reached", ErrRateLimited)
	}
	queue := l.partners[subject.PartnerID]
	if queue == nil {
		queue = &slotQueue{partner: subject.PartnerID}
		l.partners[subject.PartnerID] = queue
		l.ready = append(l.ready, queue)
	}
	queue.waiters = append(queue.waiters, waiter)
	l.waiting++
	l.schedule()
	granted := waiter.granted
	l.mu.Unlock()

	lease := &slotLease{limiter: l, weight: weight}
	if granted {
		return lease, nil
	}
	select {
	case <-waiter.ready:
		return lease, nil
	case <-ctx.Done():
		// Resolve cancellation against a concurrent grant under the lock so capacity cannot leak.
		l.mu.Lock()
		if waiter.granted {
			l.mu.Unlock()
			return lease, nil
		}
		l.remove(queue, waiter)
		l.schedule()
		l.mu.Unlock()
		return nil, ctx.Err()
	}
}

// schedule grants one FIFO head per partner turn; a blocked head reserves freed capacity.
func (l *FairSlotLimiter) schedule() {
	for len(l.ready) > 0 {
		queue := l.ready[0]
		waiter := queue.waiters[0]
		if waiter.weight > l.Capacity-l.inUse {
			return
		}
		l.ready = l.ready[1:]
		queue.waiters[0] = nil
		queue.waiters = queue.waiters[1:]
		if len(queue.waiters) == 0 {
			delete(l.partners, queue.partner)
		} else {
			l.ready = append(l.ready, queue)
		}
		l.inUse += waiter.weight
		l.waiting--
		waiter.granted = true
		close(waiter.ready)
	}
}

func (l *FairSlotLimiter) remove(queue *slotQueue, target *slotWaiter) {
	for i, waiter := range queue.waiters {
		if waiter == target {
			queue.waiters = append(queue.waiters[:i], queue.waiters[i+1:]...)
			l.waiting--
			break
		}
	}
	if len(queue.waiters) > 0 {
		return
	}
	delete(l.partners, queue.partner)
	for i, candidate := range l.ready {
		if candidate == queue {
			l.ready = append(l.ready[:i], l.ready[i+1:]...)
			return
		}
	}
}

func (l *FairSlotLimiter) release(weight int) {
	l.mu.Lock()
	l.inUse -= weight
	l.schedule()
	l.mu.Unlock()
}

type slotLease struct {
	once    sync.Once
	limiter *FairSlotLimiter
	weight  int
}

var _ port.ConcurrencyLease = (*slotLease)(nil)

func (lease *slotLease) Release() error {
	lease.once.Do(func() { lease.limiter.release(lease.weight) })
	return nil
}
