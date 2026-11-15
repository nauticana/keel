package retention

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/port"
)

// Sweeper applies its policies; a worker calls Sweep on its schedule and
// journals the counts. Every policy is validated before anything is deleted.
type Sweeper struct {
	DB       port.DatabaseRepository
	Policies []Policy
	Now      func() time.Time // nil is time.Now

	once    sync.Once
	qs      port.QueryService
	initErr error
}

func (s *Sweeper) prepare(ctx context.Context) error {
	if s.DB == nil {
		return fmt.Errorf("%w: database is required", ErrPolicy)
	}
	s.once.Do(func() {
		queries := make(map[string]string, len(s.Policies))
		for _, p := range s.Policies {
			sql, err := p.query(s.DB)
			if err == nil && queries[p.Table] != "" {
				err = fmt.Errorf("%w: %s has more than one policy", ErrPolicy, p.Table)
			}
			if err != nil {
				s.initErr = err
				return
			}
			queries[p.Table] = sql
		}
		s.qs = s.DB.GetQueryService(ctx, queries)
	})
	return s.initErr
}

// Sweep deletes every expired row in batches and returns the count per table,
// with the joined errors of the policies it could not finish.
func (s *Sweeper) Sweep(ctx context.Context) (map[string]int, error) {
	if err := s.prepare(ctx); err != nil {
		return nil, err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	deleted := make(map[string]int, len(s.Policies))
	var errs []error
	for _, p := range s.Policies {
		cutoff, batch := now().UTC().Add(-p.Window), p.batch()
		for {
			if err := ctx.Err(); err != nil {
				return deleted, errors.Join(append(errs, err)...)
			}
			res, err := s.qs.Query(ctx, p.Table, cutoff, batch)
			if err != nil {
				errs = append(errs, fmt.Errorf("retention %s: %w", p.Table, err))
				break
			}
			deleted[p.Table] += len(res.Rows)
			if len(res.Rows) < batch {
				break
			}
		}
	}
	return deleted, errors.Join(errs...)
}
