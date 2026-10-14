package pgsql

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nauticana/keel/common"
)

func TestBuildDSNSessionIsUTC(t *testing.T) {
	*common.DBhost, *common.DBuser, *common.DBname = "db.internal", "keel", "keeldb"
	cfg, err := pgx.ParseConfig(buildDSN("p,a=s s'w\\d"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.RuntimeParams["timezone"] != "UTC" {
		t.Fatalf("session timezone = %q, want UTC", cfg.RuntimeParams["timezone"])
	}
	if cfg.Password != "p,a=s s'w\\d" || cfg.Database != "keeldb" || cfg.Host != "db.internal" {
		t.Fatalf("dsn lost a field: %+v", cfg)
	}
}
