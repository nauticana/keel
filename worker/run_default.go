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

// RunDefault is the standard worker entry point for binaries that don't
// need anything beyond the keel-shipped logger / secret provider /
// snowflake id generator / pgsql database / standard quota service. It
// builds those singletons, wires them into a JobExecutor, and calls Run.
//
// Typical main:
//
//	func main() {
//	    flag.Parse()
//	    if err := worker.RunDefault(context.Background(), "matcher", 30, &worker.MatcherWorker{}); err != nil {
//	        log.Fatal(err)
//	    }
//	}
//
// Callers that need to inject extra services (custom quota, alternate
// database flavor, additional ports) should keep using JobExecutor
// directly — RunDefault is a thin convenience layer above it, not a
// replacement.
func RunDefault(ctx context.Context, caption string, intervalSec int, w JobWorker) error {
	if w == nil {
		return fmt.Errorf("RunDefault: worker is nil")
	}
	journal, err := logger.NewApplicationLogger(caption)
	if err != nil {
		return fmt.Errorf("RunDefault: logger: %w", err)
	}
	defer journal.Close()

	secrets, err := secret.NewSecretProvider(ctx)
	if err != nil {
		return fmt.Errorf("RunDefault: secrets: %w", err)
	}

	gen, err := data.NewSnowflakeGenerator(int64(*common.NodeId), data.EpochMs2026)
	if err != nil {
		return fmt.Errorf("RunDefault: snowflake: %w", err)
	}

	// Object storage is optional: only build it when --storage_mode is set.
	// A misconfigured backend (e.g. azure without --storage_account_url) is
	// a hard startup error, consistent with the secret provider.
	var objStore storage.ObjectStorage
	if mode := *common.StorageMode; mode != "" {
		objStore, err = storage.New(ctx, mode)
		if err != nil {
			return fmt.Errorf("RunDefault: storage: %w", err)
		}
	}

	executor := &JobExecutor{
		Caption:  caption,
		Interval: intervalSec,
		Journal:  journal,
		Worker:   w,
		Storage:  objStore,
		NewDatabase: func(ctx context.Context, sp secret.SecretProvider) (data.DatabaseRepository, error) {
			return pgsql.NewPgSQLDatabase(ctx, sp, gen)
		},
		NewQuota: func(db data.DatabaseRepository) port.QuotaService {
			return &service.QuotaServiceDb{Repo: db}
		},
	}
	return executor.Run(ctx, secrets)
}
