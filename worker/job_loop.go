package worker

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// JobLoop polls a queue table for pending jobs, atomically claims each one,
// and invokes a per-worker handler. It collapses the poll/claim/reclaim
// pattern every queue worker repeats:
//
//	res, _ := qs.Query(ctx, qGetPending)
//	for _, row := range res.Rows {
//	    if claimRes, _ := qs.Query(ctx, qClaim, row[0]); len(claimRes.Rows) == 0 { continue }
//	    process...
//	}
//
// The handler owns its own status-update SQL (shape varies per worker) and is
// passed the full pending row so it can read partner_id, draft_id, etc.
// directly. Retry/backoff is a handler concern: route retryable failures to a
// 'R' status with a scheduled_time and have GetPendingQuery select it.
type JobLoop struct {
	QS              port.QueryService
	Journal         logger.ApplicationLogger
	GetPendingQuery string // returns rows of claimable jobs; id is row[0]
	ClaimQuery      string // UPDATE ... SET status='A' WHERE id=? AND status IN ('P','R') RETURNING id
	WorkerName      string // for log messages

	// ReclaimQuery (optional) demotes rows stuck in 'A' from a crashed run back
	// to 'P'. Run once per tick via Reclaim. Must end with RETURNING id so the
	// demoted count is logged. Recommended shape:
	//
	//   UPDATE <queue> SET status='P', updated_at=CURRENT_TIMESTAMP
	//    WHERE status='A' AND updated_at < CURRENT_TIMESTAMP - INTERVAL '10 minutes'
	//   RETURNING id
	ReclaimQuery string

	// Leased mints a unique lease token (QS.GenID()) per claim, binds it as
	// ClaimQuery's first parameter (id is second), and passes the claim's
	// RETURNING row to the handler so it can scope completion to its own claim.
	// Off by default; set by the run paths for a LeasedQueueWorker.
	Leased bool
}

// Reclaim runs ReclaimQuery (no-op when empty), logging only when rows were
// demoted so steady-state ticks stay quiet.
func (l *JobLoop) Reclaim(ctx context.Context) {
	if l.ReclaimQuery == "" {
		return
	}
	res, err := l.QS.Query(ctx, l.ReclaimQuery)
	if err != nil {
		l.Journal.Error(fmt.Sprintf("%s: failed to reclaim stale jobs: %v", l.WorkerName, err))
		return
	}
	if res != nil && len(res.Rows) > 0 {
		l.Journal.Info(fmt.Sprintf("%s: reclaimed %d stale Active claim(s) to Pending", l.WorkerName, len(res.Rows)))
	}
}

// Run polls once and dispatches each claimed job to handle. Fetch/claim and
// handler errors are logged and the loop continues; a lost claim (no row) is
// skipped; ctx cancellation stops the drain between jobs.
func (l *JobLoop) Run(ctx context.Context, handle func(ctx context.Context, jobID int64, row []any) error) {
	res, err := l.QS.Query(ctx, l.GetPendingQuery)
	if err != nil {
		l.Journal.Error(fmt.Sprintf("%s: failed to fetch pending jobs: %v", l.WorkerName, err))
		return
	}
	for _, row := range res.Rows {
		if ctx.Err() != nil {
			return
		}
		jobID := common.AsInt64(row[0])
		claimArgs := []any{jobID}
		if l.Leased {
			claimArgs = []any{l.QS.GenID(), jobID} // token first, id second
		}
		claimRes, err := l.QS.Query(ctx, l.ClaimQuery, claimArgs...)
		if err != nil {
			l.Journal.Error(fmt.Sprintf("%s: failed to claim job %d: %v", l.WorkerName, jobID, err))
			continue
		}
		if len(claimRes.Rows) == 0 {
			continue
		}
		jobRow := row
		if l.Leased {
			jobRow = claimRes.Rows[0] // carries the lease token + projected columns
		}
		if err := handle(ctx, jobID, jobRow); err != nil {
			l.Journal.Error(fmt.Sprintf("%s: job %d failed: %v", l.WorkerName, jobID, err))
		}
	}
}
