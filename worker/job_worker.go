package worker

import (
	"context"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// Worker is the minimal contract: health port + named OLTP queries. A concrete
// worker also implements one processing contract — JobWorker or QueueWorker.
type Worker interface {
	GetHealthcheckPort() int
	GetOLTPQueries() map[string]string
}

// JobWorker drives its own per-tick pass via ProcessQueue (custom or
// multi-queue work; may run JobLoops itself).
type JobWorker interface {
	Worker
	ProcessQueue(ctx context.Context, journal logger.ApplicationLogger, db data.DatabaseRepository, quota port.QuotaService, qs data.QueryService)
}

// QueueWorker delegates the drain to the framework: it supplies the queue
// identity and one-job logic, and JobExecutor drives a JobLoop. See the README
// "Background job scheduler" section.
type QueueWorker interface {
	Worker
	// QueueQueries names the pending/claim/reclaim queries (keys into
	// GetOLTPQueries) and a short worker name; empty reclaim disables recovery.
	QueueQueries() (pending, claim, reclaim, name string)
	// HandleJob processes one claimed job; row[0] is the id. A returned error is
	// logged and the next tick re-polls.
	HandleJob(ctx context.Context, journal logger.ApplicationLogger, db data.DatabaseRepository, quota port.QuotaService, qs data.QueryService, jobID int64, row []any) error
}
