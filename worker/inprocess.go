package worker

import (
	"context"
	"time"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// RunQueueInProcess drives a QueueWorker's drain loop on a ticker over an existing
// DB connection until ctx is cancelled — for running a drain as a goroutine in
// another binary (e.g. the API) instead of a standalone worker. The atomic claim
// keeps it correct even when several replicas run it. See README for the trade-off
// against AbstractWorker.Run.
func RunQueueInProcess(ctx context.Context, qw QueueWorker, db data.DatabaseRepository, journal logger.ApplicationLogger, quota port.QuotaService, interval time.Duration) {
	qs := db.GetQueryService(ctx, qw.GetOLTPQueries())
	pending, claim, reclaim, name := qw.QueueQueries()
	loop := &JobLoop{
		QS:              qs,
		Journal:         journal,
		GetPendingQuery: pending,
		ClaimQuery:      claim,
		ReclaimQuery:    reclaim,
		WorkerName:      name,
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			loop.Reclaim(ctx)
			loop.Run(ctx, func(ctx context.Context, jobID int64, row []any) error {
				return qw.HandleJob(ctx, journal, db, quota, qs, jobID, row)
			})
		}
	}
}
