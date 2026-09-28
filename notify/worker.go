package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/worker"
)

// Worker drains pending notification rows through Sender (typically a
// dispatcher.LocalNotificationService with its channels registered). Claims are
// lease-token scoped, so replicas can drain the same table; a failed delivery is
// retried with exponential backoff until MaxAttempts, then marked failed.
type Worker struct {
	worker.AbstractWorker
	Sender      port.NotificationService
	MaxAttempts int           // default 5
	LeaseTTL    time.Duration // default 5m
	BatchLimit  int           // pending rows fetched per tick, default 50
}

var (
	_ worker.QueueWorker       = (*Worker)(nil)
	_ worker.LeasedQueueWorker = (*Worker)(nil)
)

func (w *Worker) LeaseClaim() bool { return true }

func (w *Worker) QueueQueries() (pending, claim, reclaim, name string) {
	return qPending, qClaim, qReclaim, "notify"
}

func (w *Worker) GetOLTPQueries() map[string]string {
	leaseSeconds, batch := 300, 50
	if w.LeaseTTL > 0 {
		leaseSeconds = int(w.LeaseTTL.Seconds())
	}
	if w.BatchLimit > 0 {
		batch = w.BatchLimit
	}
	return workerQueries(leaseSeconds, batch)
}

func (w *Worker) maxAttempts() int {
	if w.MaxAttempts <= 0 {
		return 5
	}
	return w.MaxAttempts
}

// HandleJob delivers one claimed row. The row id is the DedupeKey, so a
// redelivery after a lost completion write is refused by the sender's ledger
// as a duplicate and recorded as sent.
func (w *Worker) HandleJob(ctx context.Context, journal logger.ApplicationLogger, _ port.DatabaseRepository, _ port.QuotaService, qs port.QueryService, jobID int64, row []any) error {
	if w.Sender == nil {
		return ErrNoSender
	}
	attempts := int(common.AsInt64(row[8]))
	token := common.AsInt64(row[9])
	req, err := requestFromClaim(jobID, row)
	if err != nil {
		return w.transition(ctx, qs, journal, jobID, qFail, truncErr(err), jobID, token)
	}
	sendErr := w.Sender.Send(ctx, req)
	switch {
	case sendErr == nil || errors.Is(sendErr, port.ErrNotificationDuplicate):
		return w.transition(ctx, qs, journal, jobID, qSent, jobID, token)
	case errors.Is(sendErr, port.ErrNotificationSuppressed):
		return w.transition(ctx, qs, journal, jobID, qSuppressed, truncErr(sendErr), jobID, token)
	case errors.Is(sendErr, port.ErrNotificationChannel) || attempts+1 >= w.maxAttempts():
		journal.Error(fmt.Sprintf("notify %d: %s delivery failed after %d attempts: %v", jobID, req.Channel, attempts+1, sendErr))
		return w.transition(ctx, qs, journal, jobID, qFail, truncErr(sendErr), jobID, token)
	default:
		delay := backoffSeconds(attempts + 1)
		journal.Warning(fmt.Sprintf("notify %d: %s delivery failed (attempt %d), retry in %ds: %v", jobID, req.Channel, attempts+1, delay, sendErr))
		return w.transition(ctx, qs, journal, jobID, qRetry, delay, truncErr(sendErr), jobID, token)
	}
}

// transition writes an outcome scoped to the claim's lease token; no returned
// row means a reclaim handed the notification to another worker.
func (w *Worker) transition(ctx context.Context, qs port.QueryService, journal logger.ApplicationLogger, jobID int64, name string, args ...any) error {
	res, err := qs.Query(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("notify %d: record outcome: %w", jobID, err)
	}
	if len(res.Rows) == 0 {
		journal.Warning(fmt.Sprintf("notify %d: lease lost before recording the outcome", jobID))
	}
	return nil
}

func requestFromClaim(jobID int64, row []any) (port.NotificationRequest, error) {
	req := port.NotificationRequest{
		UserID:    int(common.AsInt64(row[1])),
		Type:      common.AsString(row[3]),
		Channel:   common.AsString(row[4]),
		Title:     common.AsString(row[5]),
		Body:      common.AsString(row[6]),
		DedupeKey: "notify:" + strconv.FormatInt(jobID, 10),
	}
	if partnerID, ok := common.AsInt64OK(row[2]); ok {
		req.PartnerID = partnerID
	}
	if raw := common.AsString(row[7]); raw != "" {
		if err := json.Unmarshal([]byte(raw), &req.Data); err != nil {
			return req, fmt.Errorf("notify: decode data: %w", err)
		}
	}
	return req, nil
}

// backoffSeconds is 2^attempt capped at one hour; the clamp keeps the shift
// from overflowing into a negative delay.
func backoffSeconds(attempt int) int {
	if attempt >= 12 {
		return 3600
	}
	return min(1<<max(attempt, 0), 3600)
}

func truncErr(err error) string {
	s := err.Error()
	if len(s) > 500 {
		return s[:500]
	}
	return s
}
