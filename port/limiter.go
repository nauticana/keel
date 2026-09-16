package port

import (
	"context"
	"time"

	"github.com/nauticana/keel/model"
)

// RateLimiter admits one call on a named lane for a subject; a rejection is a limiter.LimitError.
type RateLimiter interface {
	Allow(ctx context.Context, lane string, subject model.AdmissionSubject) error
}

// ConcurrencyLimiter reserves execution capacity fairly across subjects, blocking until granted.
type ConcurrencyLimiter interface {
	Acquire(ctx context.Context, subject model.AdmissionSubject) (ConcurrencyLease, error)
	// AcquireWeighted reserves weight units at once; weight must not exceed capacity.
	AcquireWeighted(ctx context.Context, subject model.AdmissionSubject, weight int) (ConcurrencyLease, error)
}

// ConcurrencyLease is reserved capacity; Release is idempotent.
type ConcurrencyLease interface {
	Release() error
}

// RetryAfterError carries advisory retry timing for a rejected operation.
type RetryAfterError interface {
	error
	RetryAfter() time.Duration
}
