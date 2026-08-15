package config

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/nauticana/keel/port"
)

var keelConfig atomic.Pointer[KeelConfig]

// ReloadFunc is set by main after the database is available. The RELOAD table action invokes it.
var ReloadFunc func(ctx context.Context) error

func init() { keelConfig.Store(&KeelConfig{}) }

// Config returns keel's active runtime configuration (never nil).
func Config() *KeelConfig { return keelConfig.Load() }

// SetConfig publishes an applied configuration; never mutate it afterwards.
func SetConfig(c *KeelConfig) { keelConfig.Store(c) }

func configText(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	if bytes, ok := value.([]byte); ok {
		return string(bytes)
	}
	return fmt.Sprint(value)
}

// LoadRows resolves the whole flag catalog for one node in a single query.
func LoadRows(ctx context.Context, db port.DatabaseRepository, nodeID int) (ConfigRows, error) {
	qs := db.GetQueryService(ctx, acQueries)
	res, err := qs.Query(ctx, qNodeConfigs, nodeID)
	if err != nil {
		return nil, fmt.Errorf("load application config for node %d: %w", nodeID, err)
	}
	rows := make(ConfigRows, len(res.Rows))
	for _, row := range res.Rows {
		rows[configText(row[0])] = ConfigRow{Value: configText(row[1]), Default: configText(row[2])}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("application_config_flag catalog is empty - seed it (schema/seed/core.yml) before starting")
	}
	return rows, nil
}

// LoadConfig loads, applies, and publishes a Keel-only application config;
// composite applications write their own loader.
func LoadConfig(ctx context.Context, db port.DatabaseRepository, nodeID int) error {
	rows, err := LoadRows(ctx, db, nodeID)
	if err != nil {
		return err
	}
	kc := &KeelConfig{}
	for _, ac := range []ApplicationConfig{kc} {
		if err = ac.Apply(rows); err != nil {
			return err
		}
	}
	SetConfig(kc)
	return err
}
