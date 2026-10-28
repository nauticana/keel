package worker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
	"github.com/nauticana/keel/service"
	"github.com/nauticana/keel/storage"
)

const (
	qRegisterService    = "register_service"
	qUpdateHeartBeat    = "update_heart_beat"
	qPruneStaleRegistry = "prune_stale_registry"
)

// MaxServiceNameLen is the service_registry.service_name width a Caption must fit.
const MaxServiceNameLen = 16

// ErrCaption is a worker Caption that is empty or longer than MaxServiceNameLen.
var ErrCaption = fmt.Errorf("worker: caption must be 1 to %d characters", MaxServiceNameLen)

func checkCaption(caption string) error {
	if n := utf8.RuneCountInString(caption); n == 0 || n > MaxServiceNameLen {
		return fmt.Errorf("%w: %q", ErrCaption, caption)
	}
	return nil
}

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
	// Heartbeats fire every 30 s, so a row silent for 5 minutes is a dead worker.
	qPruneStaleRegistry: `
DELETE FROM service_registry
 WHERE service_name = ?
   AND last_heartbeat < CURRENT_TIMESTAMP - INTERVAL '5 minutes'
`,
}

type JobExecutor struct {
	Caption  string
	Interval int
	Journal  logger.ApplicationLogger
	Worker   Worker
	// DB is the OLTP database. AbstractWorker.Run sets it after loading the
	// configured application config; standalone constructions
	// may leave it nil and supply NewDatabase instead — then the caller must load
	// config.Config() itself before Run, or DB-backed settings read as zero.
	DB          port.DatabaseRepository
	NewDatabase func(ctx context.Context, sp secret.SecretProvider) (port.DatabaseRepository, error)
	NewQuota    func(db port.DatabaseRepository) port.QuotaService

	// Storage is the optional object-storage backend for storage_bucket,
	// populated by AbstractWorker.Run when storage_mode is set (nil
	// otherwise). ProcessQueue does not receive it as a parameter to keep
	// the JobWorker interface stable; workers that need storage should hold
	// a reference to their JobExecutor, or build one per bucket via
	// storage.NewFromConfig(ctx, secrets, bucket).
	Storage storage.ObjectStorage
}

// Run refuses a Caption that cannot register (ErrCaption) and a failed
// registration, so a running worker always has a registry row and heartbeat.
// SIGTERM or SIGINT stops it with a nil error; the end of parent returns parent's error.
func (e *JobExecutor) Run(parent context.Context, secretProvider secret.SecretProvider) error {
	if err := checkCaption(e.Caption); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx = pprof.WithLabels(ctx, pprof.Labels("worker", e.Caption))
	pprof.SetGoroutineLabels(ctx)
	hcPort := e.Worker.GetHealthcheckPort()
	if config.Config().HCPort > 0 {
		hcPort = config.Config().HCPort
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

	(&service.DebugServer{Journal: e.Journal}).Start(ctx)
	e.Journal.Info("starting new service " + e.Caption)
	dbOLTP := e.DB
	if dbOLTP == nil {
		var err error
		dbOLTP, err = e.NewDatabase(ctx, secretProvider)
		if err != nil {
			return err
		}
	}
	quotaService := e.NewQuota(dbOLTP)
	if l, ok := quotaService.(quotaListener); ok {
		go e.listenQuota(ctx, l)
	}
	var qsOLTP port.QueryService
	oltpQueries := e.Worker.GetOLTPQueries()
	if len(oltpQueries) > 0 {
		qsOLTP = dbOLTP.GetQueryService(ctx, oltpQueries)
	}
	if err := e.registerService(ctx, dbOLTP.GetQueryService(ctx, ServiceQueries), e.Caption); err != nil {
		return err
	}

	// QueueWorker drains via a JobLoop the framework owns; build it once (QS +
	// query names are static) and reuse it each tick.
	var loop *JobLoop
	if qw, ok := e.Worker.(QueueWorker); ok {
		pending, claim, reclaim, name := qw.QueueQueries()
		loop = &JobLoop{QS: qsOLTP, Journal: e.Journal, GetPendingQuery: pending, ClaimQuery: claim, ReclaimQuery: reclaim, WorkerName: name, Leased: leasedClaim(qw)}
	}

	ticker := time.NewTicker(time.Duration(e.Interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			e.Journal.Info("stopping " + e.Caption + ": " + context.Cause(ctx).Error())
			return parent.Err()
		case <-ticker.C:
			e.runTick(ctx, dbOLTP, quotaService, qsOLTP, loop)
		}
	}
}

// runTick runs one pass in a panic barrier so a single bad job can't kill the
// daemon. A QueueWorker is drained via its JobLoop; a JobWorker drives its own
// ProcessQueue.
func (e *JobExecutor) runTick(ctx context.Context, dbOLTP port.DatabaseRepository, quotaService port.QuotaService, qsOLTP port.QueryService, loop *JobLoop) {
	defer func() {
		if r := recover(); r != nil {
			e.Journal.Error(fmt.Sprintf("worker: tick panic recovered: %v", r))
		}
	}()
	switch w := e.Worker.(type) {
	case QueueWorker:
		loop.Reclaim(ctx)
		loop.Run(ctx, func(ctx context.Context, jobID int64, row []any) error {
			return w.HandleJob(ctx, e.Journal, dbOLTP, quotaService, qsOLTP, jobID, row)
		})
	case JobWorker:
		w.ProcessQueue(ctx, e.Journal, dbOLTP, quotaService, qsOLTP)
	default:
		e.Journal.Error("worker: implements neither QueueWorker nor JobWorker")
	}
}

func (e *JobExecutor) registerService(ctx context.Context, qs port.QueryService, serviceName string) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	pid := int64(os.Getpid())
	// A failed prune only grows the table.
	if _, pruneErr := qs.Query(ctx, qPruneStaleRegistry, serviceName); pruneErr != nil {
		log.Printf("failed to prune stale service_registry for %s: %v", serviceName, pruneErr)
	}
	e.Journal.Info("registering service " + serviceName + " on " + hostname + " PID " + fmt.Sprint(pid))
	if _, err := qs.Query(ctx, qRegisterService, serviceName, hostname, pid); err != nil {
		return fmt.Errorf("worker %q: register service: %w", serviceName, err)
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
	return nil
}

// quotaListener is a quota service that drops limits other processes invalidate.
type quotaListener interface {
	Listen(ctx context.Context) error
}

func (e *JobExecutor) listenQuota(ctx context.Context, l quotaListener) {
	if err := l.Listen(ctx); err != nil && !errors.Is(err, context.Canceled) {
		e.Journal.Error(fmt.Sprintf("worker: quota invalidation listener stopped: %v", err))
	}
}
