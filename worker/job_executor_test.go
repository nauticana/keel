package worker

import (
	"context"
	"testing"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// --- worker test doubles (reuse fakeQS / fakeLogger / qr / anyContains) ------

type fakeQueueWorker struct {
	handled []int64
}

func (w *fakeQueueWorker) GetHealthcheckPort() int           { return 0 }
func (w *fakeQueueWorker) GetOLTPQueries() map[string]string { return nil }
func (w *fakeQueueWorker) QueueQueries() (string, string, string, string) {
	return "pending", "claim", "reclaim", "fq"
}
func (w *fakeQueueWorker) HandleJob(_ context.Context, _ logger.ApplicationLogger, _ port.DatabaseRepository, _ port.QuotaService, _ port.QueryService, jobID int64, _ []any) error {
	w.handled = append(w.handled, jobID)
	return nil
}

type fakeProcessWorker struct {
	processed int
}

func (w *fakeProcessWorker) GetHealthcheckPort() int           { return 0 }
func (w *fakeProcessWorker) GetOLTPQueries() map[string]string { return nil }
func (w *fakeProcessWorker) ProcessQueue(context.Context, logger.ApplicationLogger, port.DatabaseRepository, port.QuotaService, port.QueryService) {
	w.processed++
}

// minimalWorker satisfies only Worker — neither processing contract.
type minimalWorker struct{}

func (minimalWorker) GetHealthcheckPort() int           { return 0 }
func (minimalWorker) GetOLTPQueries() map[string]string { return nil }

var (
	_ QueueWorker = (*fakeQueueWorker)(nil)
	_ JobWorker   = (*fakeProcessWorker)(nil)
	_ Worker      = minimalWorker{}
)

// --- runTick dispatch -------------------------------------------------------

func TestJobExecutor_runTick_queueWorkerDrainsViaLoop(t *testing.T) {
	qs := &fakeQS{fixed: map[string]*model.QueryResult{
		"pending": qr([]any{int64(11)}, []any{int64(12)}),
		"claim":   qr([]any{int64(1)}),
	}}
	lg := &fakeLogger{}
	w := &fakeQueueWorker{}
	e := &JobExecutor{Journal: lg, Worker: w}
	loop := &JobLoop{QS: qs, Journal: lg, GetPendingQuery: "pending", ClaimQuery: "claim", ReclaimQuery: "reclaim", WorkerName: "fq"}

	e.runTick(context.Background(), nil, nil, qs, loop)

	if len(w.handled) != 2 || w.handled[0] != 11 || w.handled[1] != 12 {
		t.Fatalf("handled = %v, want [11 12]", w.handled)
	}
}

func TestJobExecutor_runTick_jobWorkerProcesses(t *testing.T) {
	lg := &fakeLogger{}
	w := &fakeProcessWorker{}
	e := &JobExecutor{Journal: lg, Worker: w}

	e.runTick(context.Background(), nil, nil, nil, nil)

	if w.processed != 1 {
		t.Fatalf("processed = %d, want 1", w.processed)
	}
}

func TestJobExecutor_runTick_neitherContractLogs(t *testing.T) {
	lg := &fakeLogger{}
	e := &JobExecutor{Journal: lg, Worker: minimalWorker{}}

	e.runTick(context.Background(), nil, nil, nil, nil)

	if !anyContains(lg.errs, "neither QueueWorker nor JobWorker") {
		t.Fatalf("expected neither-contract log, got %v", lg.errs)
	}
}
