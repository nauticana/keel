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
// cache invalidation, …). A non-nil error triggers retry with exponential backoff
// until MaxAttempts, after which the event is dead-lettered (status F). Event.Id
// is a stable idempotency key the destination can dedupe on.
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

// Worker drains outbox_event with lease semantics and at-least-once delivery. It
// is a LeasedQueueWorker: each claim stamps a unique lease_token and HandleJob
// scopes completion/retry/dead-letter to (id, lease_token), so a worker whose
// lease expired and was reclaimed cannot overwrite a newer claim or resurrect a
// delivered event. Run standalone via the worker runtime or in-process via
// worker.RunQueueInProcess.
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

func (w *Worker) LeaseClaim() bool { return true }

func (w *Worker) QueueQueries() (pending, claim, reclaim, name string) {
	return qPending, qClaim, qReclaim, "outbox"
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
		qPending: fmt.Sprintf(`SELECT id FROM outbox_event
			 WHERE status = 'P' AND available_at <= CURRENT_TIMESTAMP
			 ORDER BY available_at
			 LIMIT %d`, batch),
		// Token first, id second (LeasedQueueWorker contract); RETURNING projects
		// every column HandleJob reads.
		qClaim: fmt.Sprintf(`UPDATE outbox_event
			   SET status = 'A', lease_token = ?, lease_until = CURRENT_TIMESTAMP + INTERVAL '%d seconds', updated_at = CURRENT_TIMESTAMP
			 WHERE id = ? AND status = 'P'
			RETURNING id, partner_id, aggregate_type, aggregate_id, event_type, payload, attempts, lease_token`, leaseSec),
		qReclaim: `UPDATE outbox_event
			   SET status = 'P', lease_token = NULL, lease_until = NULL, updated_at = CURRENT_TIMESTAMP
			 WHERE status = 'A' AND lease_until < CURRENT_TIMESTAMP
			RETURNING id`,
		// RETURNING id so a zero-row result (lease lost to a reclaim) is detectable
		// rather than silently logged as success.
		qDone: `UPDATE outbox_event SET status = 'D', lease_token = NULL, lease_until = NULL, updated_at = CURRENT_TIMESTAMP
			 WHERE id = ? AND lease_token = ? RETURNING id`,
		qRetry: `UPDATE outbox_event
			   SET status = 'P', attempts = attempts + 1, lease_token = NULL, lease_until = NULL,
			       available_at = CURRENT_TIMESTAMP + (INTERVAL '1 second' * ?), last_error = ?, updated_at = CURRENT_TIMESTAMP
			 WHERE id = ? AND lease_token = ? RETURNING id`,
		qFail: `UPDATE outbox_event SET status = 'F', attempts = attempts + 1, lease_token = NULL, lease_until = NULL, last_error = ?, updated_at = CURRENT_TIMESTAMP
			 WHERE id = ? AND lease_token = ? RETURNING id`,
	}
}

// HandleJob dispatches one claimed event and records the outcome scoped to its
// lease token. row is the claim's RETURNING row: id, partner_id, aggregate_type,
// aggregate_id, event_type, payload, attempts, lease_token.
func (w *Worker) HandleJob(ctx context.Context, journal logger.ApplicationLogger, db data.DatabaseRepository, quota port.QuotaService, qs data.QueryService, jobID int64, row []any) error {
	if w.Dispatcher == nil {
		return fmt.Errorf("outbox: no Dispatcher configured")
	}
	partnerID := common.AsInt64(row[1])
	if partnerID < 0 {
		partnerID = 0 // NULL partner_id (not partner-scoped)
	}
	e := Event{
		Id:            jobID,
		PartnerID:     partnerID,
		AggregateType: common.AsString(row[2]),
		AggregateID:   common.AsString(row[3]),
		EventType:     common.AsString(row[4]),
		Payload:       common.AsString(row[5]),
	}
	attempts := int(common.AsInt64(row[6]))
	token := common.AsInt64(row[7])

	if derr := w.Dispatcher.Dispatch(ctx, e); derr != nil {
		if attempts+1 >= w.maxAttempts() {
			res, err := qs.Query(ctx, qFail, truncErr(derr), jobID, token)
			if err != nil {
				return fmt.Errorf("outbox %d: dead-letter write failed (event still active): %w", jobID, err)
			}
			if len(res.Rows) == 0 {
				journal.Warning(fmt.Sprintf("outbox %d: lease lost before dead-letter; another worker now owns it", jobID))
				return nil
			}
			journal.Error(fmt.Sprintf("outbox %d dead-lettered after %d attempts: %v", jobID, attempts+1, derr))
			return nil
		}
		backoff := backoffSeconds(attempts + 1)
		res, err := qs.Query(ctx, qRetry, backoff, truncErr(derr), jobID, token)
		if err != nil {
			return fmt.Errorf("outbox %d: retry write failed (event may stay claimed): %w", jobID, err)
		}
		if len(res.Rows) == 0 {
			journal.Warning(fmt.Sprintf("outbox %d: lease lost before retry; another worker now owns it", jobID))
			return nil
		}
		journal.Warning(fmt.Sprintf("outbox %d dispatch failed (attempt %d), retry in %ds: %v", jobID, attempts+1, backoff, derr))
		return nil
	}
	res, err := qs.Query(ctx, qDone, jobID, token)
	if err != nil {
		return fmt.Errorf("outbox %d: mark done failed (will be re-dispatched): %w", jobID, err)
	}
	if len(res.Rows) == 0 {
		journal.Warning(fmt.Sprintf("outbox %d: lease lost before completion; will be re-dispatched", jobID))
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

var (
	_ worker.QueueWorker       = (*Worker)(nil)
	_ worker.LeasedQueueWorker = (*Worker)(nil)
)
