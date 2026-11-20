package worker

import (
	"context"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// firstPassWorker counts its passes and stops the run after the first.
type firstPassWorker struct {
	passes int
	stop   context.CancelFunc
}

func (w *firstPassWorker) GetHealthcheckPort() int           { return 0 }
func (w *firstPassWorker) GetOLTPQueries() map[string]string { return nil }
func (w *firstPassWorker) ProcessQueue(context.Context, logger.ApplicationLogger, port.DatabaseRepository, port.QuotaService, port.QueryService) {
	w.passes++
	w.stop()
}
