package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// Defaults for a Scheduler left unconfigured.
const (
	DefaultScheduleLease      = 5 * time.Minute
	DefaultScheduleMaxBackoff = 6 * time.Hour
	scheduleErrorLimit        = 500 // last_error is a diagnosis, not a log
)

const (
	qScheduleUpsert = "work_schedule_upsert"
	qScheduleDue    = "work_schedule_due"
	qScheduleDone   = "work_schedule_complete"
	qScheduleFail   = "work_schedule_fail"
	qScheduleDrop   = "work_schedule_drop"
	qScheduleClock  = "work_schedule_clock"
)

var scheduleQueries = map[string]string{
	// The cadence is the app's; an existing row keeps its place in the rotation
	// unless its calendar cadence changed. A NULL first run means now.
	qScheduleUpsert: `
INSERT INTO work_schedule (partner_id, task_kind, interval_seconds, cadence, cadence_day, cadence_minute, time_zone, next_run_at)
VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(CAST(? AS TIMESTAMP), CURRENT_TIMESTAMP))
ON CONFLICT (partner_id, task_kind)
DO UPDATE SET interval_seconds = EXCLUDED.interval_seconds,
       cadence = EXCLUDED.cadence, cadence_day = EXCLUDED.cadence_day,
       cadence_minute = EXCLUDED.cadence_minute, time_zone = EXCLUDED.time_zone,
       next_run_at = CASE
         WHEN (work_schedule.cadence, work_schedule.cadence_day, work_schedule.cadence_minute, work_schedule.time_zone)
              IS DISTINCT FROM (EXCLUDED.cadence, EXCLUDED.cadence_day, EXCLUDED.cadence_minute, EXCLUDED.time_zone)
         THEN EXCLUDED.next_run_at ELSE work_schedule.next_run_at END
`,
	// One claim per due tenant, fleet-wide: the lease makes exactly one replica
	// the owner and a crash recoverable — the row is due again once it lapses.
	qScheduleDue: `
UPDATE work_schedule
   SET lease_until = CURRENT_TIMESTAMP + (? * INTERVAL '1 second'), lease_token = ?
 WHERE (partner_id, task_kind) IN (
        SELECT partner_id, task_kind
          FROM work_schedule
         WHERE task_kind = ?
           AND next_run_at <= CURRENT_TIMESTAMP
           AND (lease_until IS NULL OR lease_until < CURRENT_TIMESTAMP)
         ORDER BY next_run_at
         LIMIT ?
         FOR UPDATE SKIP LOCKED)
RETURNING partner_id, interval_seconds, consecutive_failures, last_run_at, lease_token,
          cadence, cadence_day, cadence_minute, time_zone
`,
	// Due-ness is reset from the clock, not from whatever the task wrote: a run
	// that produced no rows is still a run. A calendar cadence passes its next slot.
	qScheduleDone: `
UPDATE work_schedule
   SET last_run_at = CURRENT_TIMESTAMP, last_error = NULL, consecutive_failures = 0,
       lease_until = NULL, lease_token = NULL,
       next_run_at = COALESCE(CAST(? AS TIMESTAMP), CURRENT_TIMESTAMP + (interval_seconds * INTERVAL '1 second'))
 WHERE partner_id = ? AND task_kind = ? AND lease_token = ?
RETURNING partner_id
`,
	// Exponential backoff on the pre-increment failure count (first retry waits
	// one interval), capped so a permanently broken tenant is retried rarely
	// instead of every tick.
	qScheduleFail: `
UPDATE work_schedule
   SET last_run_at = CURRENT_TIMESTAMP, last_error = ?,
       consecutive_failures = consecutive_failures + 1, lease_until = NULL, lease_token = NULL,
       next_run_at = CURRENT_TIMESTAMP
         + (LEAST(interval_seconds * POWER(2, consecutive_failures), ?::DOUBLE PRECISION) * INTERVAL '1 second')
 WHERE partner_id = ? AND task_kind = ? AND lease_token = ?
RETURNING partner_id
`,
	qScheduleDrop: `
DELETE FROM work_schedule WHERE partner_id = ? AND task_kind = ?
`,
	qScheduleClock: `SELECT CURRENT_TIMESTAMP`,
}

// ErrScheduleClaimLost: the claim no longer owns the schedule — its lease
// lapsed and another worker re-claimed it, or the tenant was dropped mid-run.
// The run's outcome was not recorded; the current owner's will be.
var ErrScheduleClaimLost = errors.New("scheduler: claim lost")

// ScheduledTask is one tenant claimed for one recurring task kind.
type ScheduledTask struct {
	PartnerID           int64
	TaskKind            string
	Interval            time.Duration
	Cadence             Cadence // zero for an interval schedule
	ConsecutiveFailures int
	LastRunAt           time.Time // zero = never run
	LeaseToken          int64     // claim fence; pass this task to Complete or Fail
}

// Scheduler answers "which tenants are due for this task?" for recurring
// per-tenant work, the way JobLoop answers it for queue-shaped work. Due-ness
// lives in work_schedule rather than being re-derived from whatever table the
// task happens to write, so a run that produced nothing is still a run and a
// failing tenant backs off instead of being retried every tick.
//
// Claims are leased like JobLoop's, so a multi-replica deployment runs each
// tenant once per due window and a crashed replica's tenant becomes due again
// when the lease lapses. The interval per task, and what the task does, are the
// app's.
type Scheduler struct {
	DB         port.DatabaseRepository
	Lease      time.Duration // claim lease; 0 = DefaultScheduleLease
	MaxBackoff time.Duration // failure-backoff cap; 0 = DefaultScheduleMaxBackoff

	once sync.Once
	qs   port.QueryService
}

func (s *Scheduler) queries(ctx context.Context) (port.QueryService, error) {
	s.once.Do(func() {
		if s.DB != nil {
			s.qs = s.DB.GetQueryService(ctx, scheduleQueries)
		}
	})
	if s.qs == nil {
		return nil, fmt.Errorf("scheduler: no database configured")
	}
	return s.qs, nil
}

func (s *Scheduler) lease() time.Duration {
	if s.Lease <= 0 {
		return DefaultScheduleLease
	}
	return s.Lease
}

func (s *Scheduler) maxBackoff() time.Duration {
	if s.MaxBackoff <= 0 {
		return DefaultScheduleMaxBackoff
	}
	return s.MaxBackoff
}

// Schedule enrolls the tenant in the task at interval, or re-intervals an
// existing enrollment. It never moves an enrolled tenant's place in the
// rotation — a redeploy that re-registers every tenant must not make them all
// due at once.
func (s *Scheduler) Schedule(ctx context.Context, partnerID int64, taskKind string, interval time.Duration) error {
	if partnerID <= 0 || taskKind == "" {
		return fmt.Errorf("scheduler: partnerID and taskKind required")
	}
	if interval <= 0 {
		return fmt.Errorf("scheduler: %s interval must be positive", taskKind)
	}
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	_, err = qs.Query(ctx, qScheduleUpsert, partnerID, taskKind, durationSeconds(interval), string(CadenceInterval), nil, nil, nil, nil)
	return err
}

// ScheduleCalendar enrolls the tenant on a weekly or monthly cadence, first due
// at its next slot. Re-enrolling with the same cadence keeps the pending slot.
func (s *Scheduler) ScheduleCalendar(ctx context.Context, partnerID int64, taskKind string, cadence Cadence) error {
	if partnerID <= 0 || taskKind == "" {
		return fmt.Errorf("scheduler: partnerID and taskKind required")
	}
	var err error
	cadence, err = cadence.normalized()
	if err != nil {
		return err
	}
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	now, err := scheduleNow(ctx, qs)
	if err != nil {
		return err
	}
	_, err = qs.Query(ctx, qScheduleUpsert, partnerID, taskKind, durationSeconds(cadence.period()),
		string(cadence.Kind), cadence.Day, cadence.Minute, cadence.Location.String(), cadence.next(now))
	return err
}

// Drop removes the tenant's enrollment; the task stops being scheduled for it.
func (s *Scheduler) Drop(ctx context.Context, partnerID int64, taskKind string) error {
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	_, err = qs.Query(ctx, qScheduleDrop, partnerID, taskKind)
	return err
}

// Due claims up to limit tenants due for taskKind and returns them. Every
// claimed tenant must be resolved with Complete or Fail, or it stays leased
// until the lease lapses. The tasks are valid even when err reports a schedule
// whose failure could not be recorded.
func (s *Scheduler) Due(ctx context.Context, taskKind string, limit int) ([]ScheduledTask, error) {
	if taskKind == "" || limit <= 0 {
		return nil, fmt.Errorf("scheduler: taskKind and a positive limit required")
	}
	qs, err := s.queries(ctx)
	if err != nil {
		return nil, err
	}
	leaseToken := qs.GenID()
	res, err := qs.Query(ctx, qScheduleDue, durationSeconds(s.lease()), leaseToken, taskKind, limit)
	if err != nil {
		return nil, fmt.Errorf("scheduler: claim %s: %w", taskKind, err)
	}
	out := make([]ScheduledTask, 0, len(res.Rows))
	var failed error
	for _, row := range res.Rows {
		task := ScheduledTask{
			PartnerID:           common.AsInt64(row[0]),
			TaskKind:            taskKind,
			Interval:            time.Duration(common.AsInt64(row[1])) * time.Second,
			ConsecutiveFailures: int(common.AsInt64(row[2])),
			LeaseToken:          common.AsInt64(row[4]),
		}
		task.LastRunAt, _ = row[3].(time.Time)
		if kind := CadenceKind(common.AsString(row[5])); kind != CadenceInterval {
			task.Cadence = Cadence{Kind: kind, Day: int(common.AsInt64(row[6])), Minute: int(common.AsInt64(row[7]))}
			task.Cadence.Location, _ = time.LoadLocation(common.AsString(row[8]))
			// A task that could not be completed would run again at every lease
			// lapse, so an unusable cadence is failed here instead of handed out.
			if _, err := task.Cadence.normalized(); err != nil {
				failed = errors.Join(failed, s.Fail(ctx, task, err))
				continue
			}
		}
		out = append(out, task)
	}
	return out, failed
}

// Complete releases the claim and schedules the next run one interval out, or
// at the calendar cadence's first slot after completion.
func (s *Scheduler) Complete(ctx context.Context, task ScheduledTask) error {
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	var next any
	if task.Cadence.calendar() {
		cadence, err := task.Cadence.normalized()
		if err != nil {
			return fmt.Errorf("scheduler: complete %s for partner %d: %w", task.TaskKind, task.PartnerID, err)
		}
		now, err := scheduleNow(ctx, qs)
		if err != nil {
			return fmt.Errorf("scheduler: complete %s for partner %d: %w", task.TaskKind, task.PartnerID, err)
		}
		next = cadence.next(now)
	}
	res, err := qs.Query(ctx, qScheduleDone, next, task.PartnerID, task.TaskKind, task.LeaseToken)
	if err != nil {
		return fmt.Errorf("scheduler: complete %s for partner %d: %w", task.TaskKind, task.PartnerID, err)
	}
	return claimLost(res, task)
}

// Fail releases the claim, records the cause and backs the tenant off
// exponentially, capped at MaxBackoff.
func (s *Scheduler) Fail(ctx context.Context, task ScheduledTask, cause error) error {
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	reason := "unspecified failure"
	if cause != nil {
		reason = common.TruncateRunes(cause.Error(), scheduleErrorLimit)
	}
	res, err := qs.Query(ctx, qScheduleFail, reason, s.maxBackoff().Seconds(), task.PartnerID, task.TaskKind, task.LeaseToken)
	if err != nil {
		return fmt.Errorf("scheduler: fail %s for partner %d: %w", task.TaskKind, task.PartnerID, err)
	}
	return claimLost(res, task)
}

func durationSeconds(d time.Duration) int64 {
	seconds := d / time.Second
	if d%time.Second != 0 {
		seconds++
	}
	return int64(seconds)
}

func scheduleNow(ctx context.Context, qs port.QueryService) (time.Time, error) {
	res, err := qs.Query(ctx, qScheduleClock)
	if err != nil {
		return time.Time{}, fmt.Errorf("scheduler: read store clock: %w", err)
	}
	if res == nil || len(res.Rows) == 0 || len(res.Rows[0]) == 0 {
		return time.Time{}, errors.New("scheduler: store clock returned no value")
	}
	now := common.AsTime(res.Rows[0][0])
	if now.IsZero() {
		return time.Time{}, errors.New("scheduler: store clock returned an invalid value")
	}
	return now, nil
}

// claimLost turns a fenced write that matched nothing into ErrScheduleClaimLost
// so a superseded or dropped run never looks resolved.
func claimLost(res *model.QueryResult, task ScheduledTask) error {
	if res == nil || len(res.Rows) == 0 {
		return fmt.Errorf("%w: %s for partner %d", ErrScheduleClaimLost, task.TaskKind, task.PartnerID)
	}
	return nil
}
