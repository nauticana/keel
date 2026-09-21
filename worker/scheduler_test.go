package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
)

func newScheduler(qs *fakeQS) *Scheduler {
	s := &Scheduler{}
	s.qs = qs
	s.once.Do(func() {})
	return s
}

func TestSchedulerScheduleValidates(t *testing.T) {
	s := newScheduler(&fakeQS{})
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"no partner":  func() error { return s.Schedule(ctx, 0, "review_poll", time.Hour) },
		"no kind":     func() error { return s.Schedule(ctx, 1, "", time.Hour) },
		"no interval": func() error { return s.Schedule(ctx, 1, "review_poll", 0) },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestSchedulerScheduleUpserts(t *testing.T) {
	qs := &fakeQS{}
	if err := newScheduler(qs).Schedule(context.Background(), 7, "review_poll", 90*time.Minute); err != nil {
		t.Fatal(err)
	}
	args := qs.argsFor(qScheduleUpsert)
	if len(args) != 3 || args[0].(int64) != 7 || args[1].(string) != "review_poll" || args[2].(int64) != 5400 {
		t.Fatalf("upsert args = %v", args)
	}
}

func TestSchedulerDueClaimsUnderLease(t *testing.T) {
	last := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	qs := &fakeQS{genID: 41, fixed: map[string]*model.QueryResult{
		qScheduleDue: qr(
			[]any{int64(7), int64(3600), int64(0), last, int64(41)},
			[]any{int64(9), int64(86400), int64(2), nil, int64(41)}, // never run
		),
	}}
	s := newScheduler(qs)
	s.Lease = 90 * time.Second

	tasks, err := s.Due(context.Background(), "review_poll", 25)
	if err != nil {
		t.Fatal(err)
	}
	args := qs.argsFor(qScheduleDue)
	if args[0].(int64) != 90 || args[1].(int64) != 41 || args[2].(string) != "review_poll" || args[3].(int) != 25 {
		t.Fatalf("claim args = %v", args)
	}
	if len(tasks) != 2 {
		t.Fatalf("got %d tasks", len(tasks))
	}
	if tasks[0].PartnerID != 7 || tasks[0].Interval != time.Hour || !tasks[0].LastRunAt.Equal(last) {
		t.Errorf("first task = %+v", tasks[0])
	}
	if tasks[1].ConsecutiveFailures != 2 || !tasks[1].LastRunAt.IsZero() {
		t.Errorf("second task = %+v", tasks[1])
	}
	if tasks[1].TaskKind != "review_poll" {
		t.Errorf("task kind not carried: %+v", tasks[1])
	}
	if tasks[0].LeaseToken != 41 || tasks[1].LeaseToken != 41 {
		t.Errorf("claim fence not carried: %+v", tasks)
	}
}

func TestSchedulerDueDefaultsLease(t *testing.T) {
	qs := &fakeQS{}
	if _, err := newScheduler(qs).Due(context.Background(), "aicite", 10); err != nil {
		t.Fatal(err)
	}
	if got := qs.argsFor(qScheduleDue)[0].(int64); got != int64(DefaultScheduleLease.Seconds()) {
		t.Fatalf("lease = %d, want the default", got)
	}
}

func TestSchedulerDueValidates(t *testing.T) {
	s := newScheduler(&fakeQS{})
	if _, err := s.Due(context.Background(), "", 10); err == nil {
		t.Error("empty task kind should error")
	}
	if _, err := s.Due(context.Background(), "aicite", 0); err == nil {
		t.Error("non-positive limit should error")
	}
}

func TestSchedulerCompleteAndFail(t *testing.T) {
	qs := &fakeQS{fixed: map[string]*model.QueryResult{
		qScheduleDone: qr([]any{int64(7)}),
		qScheduleFail: qr([]any{int64(7)}),
	}}
	s := newScheduler(qs)
	s.MaxBackoff = 2 * time.Hour
	ctx := context.Background()

	task := ScheduledTask{PartnerID: 7, TaskKind: "review_poll", LeaseToken: 99}
	if err := s.Complete(ctx, task); err != nil {
		t.Fatal(err)
	}
	if args := qs.argsFor(qScheduleDone); args[0].(int64) != 7 || args[1].(string) != "review_poll" || args[2].(int64) != 99 {
		t.Fatalf("complete args = %v", args)
	}

	if err := s.Fail(ctx, task, errors.New("google said 403")); err != nil {
		t.Fatal(err)
	}
	args := qs.argsFor(qScheduleFail)
	if args[0].(string) != "google said 403" || args[1].(float64) != 7200 || args[4].(int64) != 99 {
		t.Fatalf("fail args = %v", args)
	}
}

// last_error is a diagnosis, not a log: a huge provider body is truncated.
func TestSchedulerFailTruncatesCause(t *testing.T) {
	qs := &fakeQS{fixed: map[string]*model.QueryResult{qScheduleFail: qr([]any{int64(7)})}}
	err := errors.New(strings.Repeat("x", scheduleErrorLimit*2))
	if err := newScheduler(qs).Fail(context.Background(), ScheduledTask{PartnerID: 7, TaskKind: "aicite", LeaseToken: 1}, err); err != nil {
		t.Fatal(err)
	}
	if got := qs.argsFor(qScheduleFail)[0].(string); len(got) != scheduleErrorLimit {
		t.Fatalf("last_error length = %d, want %d", len(got), scheduleErrorLimit)
	}
}

// A stale claim (lease re-claimed, or tenant dropped) must not look resolved.
func TestSchedulerResolveWithoutRowErrors(t *testing.T) {
	s := newScheduler(&fakeQS{})
	task := ScheduledTask{PartnerID: 7, TaskKind: "review_poll", LeaseToken: 1}
	if err := s.Complete(context.Background(), task); !errors.Is(err, ErrScheduleClaimLost) {
		t.Errorf("Complete: err = %v, want ErrScheduleClaimLost", err)
	}
	if err := s.Fail(context.Background(), task, nil); !errors.Is(err, ErrScheduleClaimLost) {
		t.Errorf("Fail: err = %v, want ErrScheduleClaimLost", err)
	}
}

func TestSchedulerRoundsSubsecondDurationsUp(t *testing.T) {
	qs := &fakeQS{}
	s := newScheduler(qs)
	s.Lease = time.Millisecond
	if err := s.Schedule(context.Background(), 1, "k", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got := qs.argsFor(qScheduleUpsert)[2]; got != int64(1) {
		t.Fatalf("interval seconds = %v, want 1", got)
	}
	if _, err := s.Due(context.Background(), "k", 1); err != nil {
		t.Fatal(err)
	}
	if got := qs.argsFor(qScheduleDue)[0]; got != int64(1) {
		t.Fatalf("lease seconds = %v, want 1", got)
	}
}

func TestSchedulerWithoutDatabase(t *testing.T) {
	s := &Scheduler{}
	if err := s.Schedule(context.Background(), 1, "k", time.Hour); err == nil {
		t.Error("an unconfigured scheduler must fail loudly")
	}
}
