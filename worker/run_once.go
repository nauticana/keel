package worker

import (
	"context"
	"flag"
	"fmt"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/pgsql"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
	"github.com/nauticana/keel/service"
)

// RunOnce executes a JobWorker's ProcessQueue exactly once and returns —
// for infrequent jobs (weekly / monthly payouts) scheduled by an external
// cron / systemd timer, rather than AbstractWorker, which is a long-lived
// daemon that starts a healthcheck server and waits a full interval
// before its FIRST run (a weekly daemon would idle for 7 days and lose
// alignment on restart).
//
// It composes the same building blocks AbstractWorker uses (secrets,
// snowflake id generator, pgsql database, runtime config, quota, query
// service, logger) minus the daemon-only pieces — healthcheck listener,
// service-registry heartbeat, and the ticker loop.
//
// loadConfig loads the runtime configuration once the DB is up; nil
// loads a plain common.BaseConfig (same default as AbstractWorker).
// pick runs after config is loaded so job selection can read config
// flags; it returns the worker and the journal caption.
func RunOnce(ctx context.Context, loadConfig func(ctx context.Context, db port.DatabaseRepository) error, pick func() (JobWorker, string, error)) error {
	if !flag.Parsed() {
		flag.Parse()
	}
	secrets, err := secret.NewSecretProvider(ctx)
	if err != nil {
		return fmt.Errorf("RunOnce: secrets: %w", err)
	}
	gen, err := data.NewSnowflakeGenerator(int64(*common.NodeId), data.EpochMs2026)
	if err != nil {
		return fmt.Errorf("RunOnce: snowflake: %w", err)
	}
	db, err := pgsql.NewPgSQLDatabase(ctx, secrets, gen)
	if err != nil {
		return fmt.Errorf("RunOnce: database: %w", err)
	}
	if loadConfig == nil {
		loadConfig = func(ctx context.Context, db port.DatabaseRepository) error {
			cfg := &common.BaseConfig{}
			if err := cfg.Load(ctx, db); err != nil {
				return err
			}
			common.SetConfig(cfg)
			return nil
		}
	}
	if err := loadConfig(ctx, db); err != nil {
		return fmt.Errorf("RunOnce: config: %w", err)
	}

	w, caption, err := pick()
	if err != nil {
		return err
	}
	journal, err := logger.NewApplicationLogger(caption)
	if err != nil {
		return fmt.Errorf("RunOnce: logger: %w", err)
	}
	defer journal.Close()

	qs := db.GetQueryService(ctx, w.GetOLTPQueries())
	quota := &service.QuotaServiceDb{Repo: db}
	journal.Info(caption + ": running once")
	w.ProcessQueue(ctx, journal, db, quota, qs)
	journal.Info(caption + ": done")
	return nil
}
