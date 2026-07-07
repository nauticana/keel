package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// RunQueueInProcess drives a QueueWorker on a ticker over an existing DB
// connection until ctx is cancelled, panic-guarding each tick — for a light drain
// run as a goroutine in another binary. Heavy or long-running work belongs in a
// standalone binary via AbstractWorker.Run.
func RunQueueInProcess(ctx context.Context, w QueueWorker, db port.DatabaseRepository, journal logger.ApplicationLogger, quota port.QuotaService, interval time.Duration) {
	qs := db.GetQueryService(ctx, w.GetOLTPQueries())
	pending, claim, reclaim, name := w.QueueQueries()
	loop := &JobLoop{QS: qs, Journal: journal, GetPendingQuery: pending, ClaimQuery: claim, ReclaimQuery: reclaim, WorkerName: name, Leased: leasedClaim(w)}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runQueueTick(ctx, w, db, quota, qs, journal, loop)
		}
	}
}

func runQueueTick(ctx context.Context, w QueueWorker, db port.DatabaseRepository, quota port.QuotaService, qs port.QueryService, journal logger.ApplicationLogger, loop *JobLoop) {
	defer func() {
		if r := recover(); r != nil {
			journal.Error(fmt.Sprintf("in-process worker tick panic recovered: %v", r))
		}
	}()
	loop.Reclaim(ctx)
	loop.Run(ctx, func(ctx context.Context, jobID int64, row []any) error {
		return w.HandleJob(ctx, journal, db, quota, qs, jobID, row)
	})
}
