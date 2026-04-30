package worker

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

const (
	qRegisterService = "register_service"
	qUpdateHeartBeat = "update_heart_beat"
)

var ServiceQueries = map[string]string{
	qRegisterService: `
INSERT INTO service_registry
 (service_name, hostname, pid, status, started_at, last_heartbeat)
VALUES
 (?, ?, ?, 'A', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`,
	qUpdateHeartBeat: `
UPDATE service_registry
   SET last_heartbeat = CURRENT_TIMESTAMP
 WHERE service_name = ?
   AND hostname = ?
   AND started_at = (SELECT MAX(started_at) FROM service_registry WHERE service_name = ? AND hostname = ?)
`,
}

type JobExecutor struct {
	Caption     string
	Interval    int
	Journal     logger.ApplicationLogger
	Worker      JobWorker
	NewDatabase func(ctx context.Context, sp secret.SecretProvider) (data.DatabaseRepository, error)
	NewQuota    func(db data.DatabaseRepository) port.QuotaService
}

func (e *JobExecutor) Run(ctx context.Context, secretProvider secret.SecretProvider) error {
	// Start the health-check listener with explicit Server (not the
	// http.ListenAndServe convenience function) so we can call
	// Shutdown on graceful exit and free the port (P1-56). Bind
	// errors are surfaced through the journal — previously they
	// were silently dropped (P1-55).
	hcPort := e.Worker.GetHealthcheckPort()
	if *common.HCPort > 0 {
		hcPort = *common.HCPort
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	hcServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", hcPort),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("health check listening on %s", hcServer.Addr)
		if err := hcServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			e.Journal.Error(fmt.Sprintf("worker: health-check listener: %v", err))
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hcServer.Shutdown(shutdownCtx)
	}()

	e.Journal.Info("starting new service " + e.Caption)
	dbOLTP, err := e.NewDatabase(ctx, secretProvider)
	if err != nil {
		return err
	}
	quotaService := e.NewQuota(dbOLTP)
	var qsOLTP data.QueryService
	oltpQueries := e.Worker.GetOLTPQueries()
	if len(oltpQueries) > 0 {
		qsOLTP = dbOLTP.GetQueryService(ctx, oltpQueries)
	}
	e.registerService(ctx, dbOLTP.GetQueryService(ctx, ServiceQueries), e.Caption)
	ticker := time.NewTicker(time.Duration(e.Interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// P1-54: panic recovery so a single bad job doesn't
			// take down the daemon. The recover'd error is logged;
			// the next tick re-runs ProcessQueue cleanly.
			e.runProcessQueue(ctx, dbOLTP, quotaService, qsOLTP)
		}
	}
}

// runProcessQueue invokes Worker.ProcessQueue inside a panic-safety
// barrier. Crashes inside user-supplied job handlers must not kill
// the executor — the next tick should re-attempt processing.
func (e *JobExecutor) runProcessQueue(ctx context.Context, dbOLTP data.DatabaseRepository, quotaService port.QuotaService, qsOLTP data.QueryService) {
	defer func() {
		if r := recover(); r != nil {
			e.Journal.Error(fmt.Sprintf("worker: ProcessQueue panic recovered: %v", r))
		}
	}()
	e.Worker.ProcessQueue(ctx, e.Journal, dbOLTP, quotaService, qsOLTP)
}

func (e *JobExecutor) registerService(ctx context.Context, qs data.QueryService, serviceName string) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	pid := int64(os.Getpid())
	e.Journal.Info("registering service " + serviceName + " on " + hostname + " PID " + fmt.Sprint(pid))
	_, err = qs.Query(ctx, qRegisterService, serviceName, hostname, pid)
	if err != nil {
		log.Printf("failed to register service: %v", err)
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, err := qs.Query(ctx, qUpdateHeartBeat, serviceName, hostname, serviceName, hostname)
				if err != nil {
					log.Printf("failed to update heart beat for service %s: %v", serviceName, err)
				}
			}
		}
	}()
}
