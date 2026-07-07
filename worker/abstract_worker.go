package worker

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/pgsql"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
	"github.com/nauticana/keel/service"
	"github.com/nauticana/keel/storage"
)

// AbstractWorker is the embed-only base for a JobExecutor-driven worker. Embed
// it, set Caption / Interval / HCPort, implement GetOLTPQueries plus one of the
// processing contracts (JobWorker or QueueWorker), then call w.Run(ctx, w) from
// main. Run builds the keel runtime and publishes the secret provider on .Secret
// before the loop. See the README "Background job scheduler" section.
type AbstractWorker struct {
	Caption  string                // journal/log caption
	Interval int                   // poll interval, seconds
	HCPort   int                   // /health port
	Secret   secret.SecretProvider // set by Run before the loop; for AI/OAuth workers
	Storage  storage.ObjectStorage // set by Run when storage_mode is set; nil otherwise
	// LoadConfig loads the runtime configuration once the DB is up, before
	// anything reads common.Config() (storage backend, HC port, tunables). Nil
	// loads a plain common.BaseConfig into common.Config(); workers whose app
	// embeds BaseConfig set this to load their own type.
	LoadConfig func(ctx context.Context, db port.DatabaseRepository) error
}

func (a *AbstractWorker) GetHealthcheckPort() int { return a.HCPort }

// Run is the worker entry point. self is the concrete worker — pass the embedder
// (w.Run(ctx, w)); Go has no virtual dispatch, so the base can't reach the
// embedder's processing methods without it.
func (a *AbstractWorker) Run(ctx context.Context, self Worker) error {
	journal, err := logger.NewApplicationLogger(a.Caption)
	if err != nil {
		return fmt.Errorf("worker %q: logger: %w", a.Caption, err)
	}
	defer journal.Close()

	secrets, err := secret.NewSecretProvider(ctx)
	if err != nil {
		return fmt.Errorf("worker %q: secrets: %w", a.Caption, err)
	}
	a.Secret = secrets

	gen, err := data.NewSnowflakeGenerator(int64(*common.NodeId), data.EpochMs2026)
	if err != nil {
		return fmt.Errorf("worker %q: snowflake: %w", a.Caption, err)
	}

	// The DB comes up first: the runtime config lives in it, and everything
	// below (storage backend, HC port, tunables) reads common.Config().
	db, err := pgsql.NewPgSQLDatabase(ctx, secrets, gen)
	if err != nil {
		return fmt.Errorf("worker %q: database: %w", a.Caption, err)
	}
	loadConfig := a.LoadConfig
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
		return fmt.Errorf("worker %q: config: %w", a.Caption, err)
	}

	// Object storage is optional; the factory picks the backend + credential source.
	objStore, err := storage.NewFromConfig(ctx, secrets)
	if err != nil {
		return fmt.Errorf("worker %q: storage: %w", a.Caption, err)
	}
	a.Storage = objStore // expose to the concrete worker, not just the executor

	executor := &JobExecutor{
		Caption:  a.Caption,
		Interval: a.Interval,
		Journal:  journal,
		Worker:   self,
		Storage:  objStore,
		DB:       db,
		NewQuota: func(db port.DatabaseRepository) port.QuotaService {
			return &service.QuotaServiceDb{Repo: db}
		},
	}
	return executor.Run(ctx, secrets)
}
