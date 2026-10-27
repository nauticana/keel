package service

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
)

type infoLogger struct {
	logger.ApplicationLogger
	info []string
}

func (l *infoLogger) Info(log string)  { l.info = append(l.info, log) }
func (l *infoLogger) Error(log string) { l.info = append(l.info, "error: "+log) }

func TestNewServerAppliesHeaderValueLimit(t *testing.T) {
	saved := config.Config().HttpMaxHeaderValues
	t.Cleanup(func() { config.Config().HttpMaxHeaderValues = saved })
	config.Config().HttpMaxHeaderValues = 64
	if got := (&HttpBackend{}).newServer(8080).MaxHeaderValueCount; got != 64 {
		t.Errorf("MaxHeaderValueCount = %d, want 64", got)
	}
}

func TestRunStopsWhenContextEnds(t *testing.T) {
	saved := config.Config().HttpApiPort
	t.Cleanup(func() { config.Config().HttpApiPort = saved })
	config.Config().HttpApiPort = 0
	journal := &infoLogger{}
	h := &HttpBackend{Journal: journal}
	h.Handle(map[string]func(http.ResponseWriter, *http.Request){"/x": func(http.ResponseWriter, *http.Request) {}})

	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan struct{})
	go func() {
		h.Run(ctx)
		close(done)
	}()
	cancel(errors.New("deploy"))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
	if !slices.Contains(journal.info, "shutting down server: deploy") {
		t.Errorf("journal = %v, want the cause logged", journal.info)
	}
}
