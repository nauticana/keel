package outbox

import (
	"context"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/worker"
)

// Dispatcher delivers one drained event to its destination (email, queue, HTTP,
// cache invalidation, …). A non-nil error triggers retry with exponential
// backoff until MaxAttempts, after which the event is dead-lettered (status F).
type Dispatcher interface {
	Dispatch(ctx context.Context, e Event) error
}

const (
	qPending = "keel_outbox_pending"
	qClaim   = "keel_outbox_claim"
	qReclaim = "keel_outbox_reclaim"
	qDone    = "keel_outbox_done"
	qRetry   = "keel_outbox_retry"
	qFail    = "keel_outbox_fail"
)

// Worker drains outbox_event with lease semantics and at-least-once delivery:
// claim sets lease_until (crashed claims are reclaimed), failures back off, and an
// event dead-letters after MaxAttempts. Run it in-process via
// worker.RunQueueInProcess or as a standalone binary via w.Run.
type Worker struct {
	worker.AbstractWorker
	Dispatcher  Dispatcher
	MaxAttempts int           // dead-letter after this many failed dispatches (default 5)
	LeaseTTL    time.Duration // claim lease duration (default 5m)
	BatchLimit  int           // pending rows fetched per tick (default 50)
}

func (w *Worker) maxAttempts() int {
	if w.MaxAttempts <= 0 {
		return 5
	}
	return w.MaxAttempts
}

func (w *Worker) GetOLTPQueries() map[string]string {
	leaseSec := 300
	if w.LeaseTTL > 0 {
		leaseSec = int(w.LeaseTTL.Seconds())
	}
	batch := 50
	if w.BatchLimit > 0 {
		batch = w.BatchLimit
	}
	return map[string]string{
		qPending: fmt.Sprintf(`SELECT id, partner_id, aggregate_type, aggregate_id, event_type, payload, attempts
			  FROM outbox_event
			 WHERE status = 'P' AND available_at <= CURRENT_TIMESTAMP
			 ORDER BY available_at
			 LIMIT %d`, batch),
		qClaim: fmt.Sprintf(`UPDATE outbox_event
			   SET status = 'A', lease_until = CURRENT_TIMESTAMP + INTERVAL '%d seconds', updated_at = CURRENT_TIMESTAMP
			 WHERE id = ? AND status = 'P'
			RETURNING id`, leaseSec),
		qReclaim: `UPDATE outbox_event
			   SET status = 'P', lease_until = NULL, updated_at = CURRENT_TIMESTAMP
			 WHERE status = 'A' AND lease_until < CURRENT_TIMESTAMP
			RETURNING id`,
		qDone: `UPDATE outbox_event SET status = 'D', lease_until = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		qRetry: `UPDATE outbox_event
			   SET status = 'P', attempts = attempts + 1, lease_until = NULL,
			       available_at = CURRENT_TIMESTAMP + (INTERVAL '1 second' * ?), last_error = ?, updated_at = CURRENT_TIMESTAMP
			 WHERE id = ?`,
		qFail: `UPDATE outbox_event SET status = 'F', attempts = attempts + 1, lease_until = NULL, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
	}
}

func (w *Worker) QueueQueries() (pending, claim, reclaim, name string) {
	return qPending, qClaim, qReclaim, "outbox"
}

func (w *Worker) HandleJob(ctx context.Context, journal logger.ApplicationLogger, db data.DatabaseRepository, quota port.QuotaService, qs data.QueryService, jobID int64, row []any) error {
	if w.Dispatcher == nil {
		return fmt.Errorf("outbox: no Dispatcher configured")
	}
	e := Event{
		PartnerID:     common.AsInt64(row[1]),
		AggregateType: common.AsString(row[2]),
		AggregateID:   common.AsString(row[3]),
		EventType:     common.AsString(row[4]),
		Payload:       common.AsString(row[5]),
	}
	attempts := int(common.AsInt64(row[6]))

	if err := w.Dispatcher.Dispatch(ctx, e); err != nil {
		if attempts+1 >= w.maxAttempts() {
			_, _ = qs.Query(ctx, qFail, truncErr(err), jobID)
			return fmt.Errorf("outbox %d dead-lettered after %d attempts: %w", jobID, attempts+1, err)
		}
		backoff := backoffSeconds(attempts + 1)
		_, _ = qs.Query(ctx, qRetry, backoff, truncErr(err), jobID)
		return fmt.Errorf("outbox %d dispatch failed (attempt %d), retry in %ds: %w", jobID, attempts+1, backoff, err)
	}
	if _, err := qs.Query(ctx, qDone, jobID); err != nil {
		return fmt.Errorf("outbox %d mark done: %w", jobID, err)
	}
	return nil
}

// backoffSeconds is exponential (2^attempt) capped at one hour.
func backoffSeconds(attempt int) int {
	s := 1 << attempt
	if s > 3600 {
		return 3600
	}
	return s
}

func truncErr(err error) string {
	s := err.Error()
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

var _ worker.QueueWorker = (*Worker)(nil)
