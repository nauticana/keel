package erasure

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
	"github.com/nauticana/keel/worker"
)

const maxAttempts = 5

// Worker executes pending erasure requests under a lease. A request whose user
// is under legal hold parks as held and resumes after release; a failing one
// retries with backoff and fails after maxAttempts.
type Worker struct {
	worker.AbstractWorker
	// NewService builds the Service on the worker's database before the first job.
	NewService func(ctx context.Context, db port.DatabaseRepository) (*Service, error)

	mu      sync.Mutex
	service *Service
}

func (w *Worker) erasure(ctx context.Context, db port.DatabaseRepository) (*Service, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.service == nil {
		if w.NewService == nil {
			return nil, fmt.Errorf("erasure: Worker.NewService is not set")
		}
		svc, err := w.NewService(ctx, db)
		if err != nil {
			return nil, err
		}
		w.service = svc
	}
	return w.service, nil
}

func (w *Worker) LeaseClaim() bool { return true }

func (w *Worker) QueueQueries() (pending, claim, reclaim, name string) {
	return qWorkerPending, qWorkerClaim, qWorkerReclaim, "erasure"
}

func (w *Worker) GetOLTPQueries() map[string]string { return queries }

// HandleJob runs one claimed request; row is the claim's RETURNING row:
// id, user_id, attempts, lease_token.
func (w *Worker) HandleJob(ctx context.Context, journal logger.ApplicationLogger, db port.DatabaseRepository, _ port.QuotaService, qs port.QueryService, jobID int64, row []any) error {
	userID, attempts, token := int(common.AsInt64(row[1])), int(common.AsInt64(row[2])), common.AsInt64(row[3])
	svc, err := w.erasure(ctx, db)
	if err != nil {
		return err
	}
	runErr := svc.Execute(ctx, jobID, userID)
	var res *model.QueryResult
	switch {
	case runErr == nil:
		res, err = qs.Query(ctx, qWorkerDone, jobID, token)
	case errors.Is(runErr, user.ErrLegalHold):
		journal.Info(fmt.Sprintf("erasure %d: user under legal hold, request parked", jobID))
		res, err = qs.Query(ctx, qWorkerHeld, jobID, token)
	case attempts+1 >= maxAttempts:
		journal.Error(fmt.Sprintf("erasure %d failed after %d attempts: %v", jobID, attempts+1, runErr))
		res, err = qs.Query(ctx, qWorkerFail, runErr.Error(), jobID, token)
	default:
		journal.Warning(fmt.Sprintf("erasure %d attempt %d failed, retrying: %v", jobID, attempts+1, runErr))
		res, err = qs.Query(ctx, qWorkerRetry, runErr.Error(), 1<<attempts, jobID, token)
	}
	if err != nil {
		return fmt.Errorf("erasure %d: record outcome: %w", jobID, err)
	}
	if len(res.Rows) == 0 {
		journal.Warning(fmt.Sprintf("erasure %d: lease lost before recording the outcome; the next claim resumes it", jobID))
	}
	return nil
}

var (
	_ worker.QueueWorker       = (*Worker)(nil)
	_ worker.LeasedQueueWorker = (*Worker)(nil)
)
