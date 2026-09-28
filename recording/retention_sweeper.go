package recording

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/storage"
)

const sweepBatch = 100

// RetentionSweeper deletes the objects of ready media completed longer than
// Retention ago and marks the rows purged. Sessions Hold reports held are
// skipped. Call Sweep from a worker on its interval.
type RetentionSweeper struct {
	DB        port.DatabaseRepository
	Storage   storage.ObjectStorage
	Retention time.Duration
	Hold      func(ctx context.Context, s Session) (bool, error)

	once sync.Once
	qs   port.QueryService
}

// Sweep purges every due object and returns how many it purged, with the
// joined errors of the sessions or objects it had to skip.
func (s *RetentionSweeper) Sweep(ctx context.Context) (int, error) {
	if s.DB == nil || s.Storage == nil || s.Retention <= 0 {
		return 0, fmt.Errorf("recording: RetentionSweeper needs DB, Storage and a positive Retention")
	}
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, queries) })
	cutoff := time.Now().UTC().Add(-s.Retention)
	var (
		purged       int
		skipped      []error
		afterSession int64
	)
	for {
		res, err := s.qs.Query(ctx, qSessionsWithDueMedia, cutoff, afterSession, sweepBatch)
		if err != nil {
			return purged, errors.Join(append(skipped, err)...)
		}
		for _, row := range res.Rows {
			afterSession = common.AsInt64(row[0])
			n, err := s.sweepSession(ctx, afterSession, cutoff)
			purged += n
			if err != nil {
				skipped = append(skipped, fmt.Errorf("recording session %d: %w", afterSession, err))
			}
		}
		if len(res.Rows) < sweepBatch {
			return purged, errors.Join(skipped...)
		}
	}
}

func (s *RetentionSweeper) sweepSession(ctx context.Context, sessionID int64, cutoff time.Time) (int, error) {
	if s.Hold != nil {
		session, err := loadSession(ctx, s.qs, qGetSession, sessionID)
		if err != nil {
			return 0, err
		}
		if held, err := s.Hold(ctx, session.Session); err != nil || held {
			return 0, err
		}
	}
	res, err := s.qs.Query(ctx, qDueMedia, sessionID, cutoff)
	if err != nil {
		return 0, err
	}
	purged := 0
	var skipped []error
	for _, row := range res.Rows {
		media := mediaFromRow(row)
		if media.Bucket != s.Storage.Bucket() {
			skipped = append(skipped, fmt.Errorf("media %d is in bucket %q, storage is bound to %q", media.ID, media.Bucket, s.Storage.Bucket()))
			continue
		}
		if err := s.Storage.DeleteObject(ctx, media.ObjectKey); err != nil && !errors.Is(err, storage.ErrNotFound) {
			skipped = append(skipped, fmt.Errorf("media %d: %w", media.ID, err))
			continue
		}
		if _, err := s.qs.Query(ctx, qSetMediaPurged, media.ID); err != nil {
			return purged, errors.Join(append(skipped, err)...)
		}
		purged++
	}
	return purged, errors.Join(skipped...)
}
