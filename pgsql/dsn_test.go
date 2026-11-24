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

// An unquoted empty value would take the next key=value pair as its own.
func TestPgxKVQuotesEmptyValue(t *testing.T) {
	cfg, err := pgx.ParseConfig("host=h user=u password=" + pgxKV("") + " dbname=d")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "" || cfg.Database != "d" {
		t.Fatalf("password %q database %q", cfg.Password, cfg.Database)
	}
}
