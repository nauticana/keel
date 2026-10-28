package worker

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/nauticana/keel/port"
)

type fakeDB struct {
	port.DatabaseRepository
	qs *fakeQS
}

func (d fakeDB) GetQueryService(context.Context, map[string]string) port.QueryService { return d.qs }

func newRunExecutor(lg *fakeLogger) *JobExecutor {
	return &JobExecutor{
		Caption: "runtest", Interval: 3600, Journal: lg, Worker: minimalWorker{},
		DB: fakeDB{qs: &fakeQS{}}, NewQuota: func(port.DatabaseRepository) port.QuotaService { return nil },
	}
}

func TestJobExecutorRunStopsCleanlyOnSIGTERM(t *testing.T) {
	keepAlive := make(chan os.Signal, 1) // the test binary survives a signal sent before Run listens
	signal.Notify(keepAlive, syscall.SIGTERM)
	defer signal.Stop(keepAlive)

	lg := &fakeLogger{}
	done := make(chan error, 1)
	go func() { done <- newRunExecutor(lg).Run(context.Background(), nil) }()
	deadline := time.After(5 * time.Second)
	for {
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Run = %v, want nil after SIGTERM", err)
			}
			if !slices.Contains(lg.infos, "stopping runtest: terminated signal received") {
				t.Errorf("journal = %v, want the signal logged", lg.infos)
			}
			return
		case <-deadline:
			t.Fatal("Run did not return after SIGTERM")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestJobExecutorRunReturnsParentError(t *testing.T) {
	lg := &fakeLogger{}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("deploy"))
	if err := newRunExecutor(lg).Run(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if !slices.Contains(lg.infos, "stopping runtest: deploy") {
		t.Errorf("journal = %v, want the cause logged", lg.infos)
	}
}
