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

// LeasedQueueWorker is an optional QueueWorker extension for at-least-once queues
// that must stay correct across lease expiry. When LeaseClaim returns true, the
// loop mints a unique lease token per claim, binds it as the claim query's first
// parameter (the id is second), and hands HandleJob the claim's RETURNING row
// (not the pending row) — so the handler reads the token and scopes its
// completion to its own claim, preventing a stale worker whose lease expired and
// was reclaimed from overwriting a newer claim. The claim RETURNING must project
// every column HandleJob reads, including the token.
type LeasedQueueWorker interface {
	QueueWorker
	LeaseClaim() bool
}

// leasedClaim reports whether w opts into per-claim lease tokens.
func leasedClaim(w Worker) bool {
	lw, ok := w.(LeasedQueueWorker)
	return ok && lw.LeaseClaim()
}
