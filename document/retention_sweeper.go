package document

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/dms"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/storage"
)

const sweepBatch = 100

// RetentionSweeper deletes the objects of documents retired longer than After
// ago and stamps purged_at, so the row keeps its trace. Call Sweep from a
// worker on its interval. A document that cannot be deleted (repository
// read-only, migrating or gone) is skipped and reported; the sweep goes on.
type RetentionSweeper struct {
	DB    port.DatabaseRepository
	Docs  *dms.ContentDocumentService
	After time.Duration // must be positive
	Now   func() time.Time

	once sync.Once
	qs   port.QueryService
}

// Sweep purges every due document and returns how many it purged, with the
// joined errors of the rows it had to skip.
func (s *RetentionSweeper) Sweep(ctx context.Context) (int, error) {
	if s.After <= 0 {
		return 0, fmt.Errorf("document: RetentionSweeper.After must be positive")
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, queries) })
	qs := s.qs
	cutoff := now().UTC().Add(-s.After)
	var (
		purged  int
		skipped []error
		afterAt = time.Time{}
		afterID int64
	)
	for {
		res, err := qs.Query(ctx, qRetiredBefore, cutoff, afterAt, afterID, sweepBatch)
		if err != nil {
			return purged, errors.Join(append(skipped, err)...)
		}
		for _, r := range res.Rows {
			id, contRep, docKey := common.AsInt64(r[0]), common.AsString(r[1]), common.AsString(r[2])
			afterAt, afterID = common.AsTime(r[3]), id
			if err := s.Docs.Delete(ctx, contRep, docKey); err != nil && !errors.Is(err, storage.ErrNotFound) && !dms.Succeeded(err) {
				skipped = append(skipped, fmt.Errorf("document %d: %w", id, err))
				continue
			}
			if _, err := qs.Query(ctx, qSetPurged, id); err != nil {
				return purged, errors.Join(append(skipped, err)...)
			}
			purged++
		}
		if len(res.Rows) < sweepBatch {
			return purged, errors.Join(skipped...)
		}
	}
}
