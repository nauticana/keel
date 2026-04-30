package worker

import (
	"context"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

type JobWorker interface {
	GetHealthcheckPort() int
	ProcessQueue(ctx context.Context, journal logger.ApplicationLogger, db data.DatabaseRepository, quota port.QuotaService, qs data.QueryService)
	GetOLTPQueries() map[string]string
}
