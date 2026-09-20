package sqlsmoke

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type fakeDB struct {
	executed []string
	prepared map[string]string
	order    []string
	reject   string
}

func (f *fakeDB) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "BROKEN") {
		return pgconn.CommandTag{}, errors.New("syntax error")
	}
	f.executed = append(f.executed, sql)
	return pgconn.CommandTag{}, nil
}

func (f *fakeDB) Prepare(_ context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	if f.prepared == nil {
		f.prepared = map[string]string{}
	}
	if _, dup := f.prepared[name]; dup {
		return nil, errors.New("duplicate statement name " + name)
	}
	f.prepared[name] = sql
	f.order = append(f.order, sql)
	if f.reject != "" && strings.Contains(sql, f.reject) {
		return nil, errors.New(`column "gone" does not exist`)
	}
	return &pgconn.StatementDescription{}, nil
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSchemaRunsFilesInOrder(t *testing.T) {
	dir := t.TempDir()
	db := &fakeDB{}
	err := LoadSchema(context.Background(), db,
		writeFile(t, dir, "b.sql", "CREATE TABLE b()"), writeFile(t, dir, "a.sql", "CREATE TABLE a()"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"CREATE TABLE b()", "CREATE TABLE a()"}; !reflect.DeepEqual(db.executed, want) {
		t.Fatalf("executed = %v", db.executed)
	}
}

func TestLoadSchemaNamesTheFailingFile(t *testing.T) {
	dir := t.TempDir()
	db := &fakeDB{}
	if err := LoadSchema(context.Background(), db, filepath.Join(dir, "missing.sql")); err == nil || !strings.Contains(err.Error(), "missing.sql") {
		t.Fatalf("missing file: err = %v", err)
	}
	if err := LoadSchema(context.Background(), db, writeFile(t, dir, "bad.sql", "BROKEN")); err == nil || !strings.Contains(err.Error(), "bad.sql") {
		t.Fatalf("bad ddl: err = %v", err)
	}
}

func TestPrepareAllRewritesPlaceholdersAndReportsFailures(t *testing.T) {
	db := &fakeDB{reject: "gone"}
	failures := PrepareAll(context.Background(), db, map[string]map[string]string{
		"worker": {
			"by_id":    "SELECT '?' FROM t WHERE id = ? AND data ?? 'k' -- why?",
			"bad_cols": "SELECT gone FROM t WHERE id = ?",
		},
		"analytics": {"all": "SELECT 1"},
	})
	want := []string{
		"SELECT 1",
		"SELECT gone FROM t WHERE id = $1",
		"SELECT '?' FROM t WHERE id = $1 AND data ? 'k' -- why?",
	}
	if !reflect.DeepEqual(db.order, want) {
		t.Fatalf("prepared = %q", db.order)
	}
	if len(failures) != 1 || failures[0].Group != "worker" || failures[0].Query != "bad_cols" {
		t.Fatalf("failures = %v", failures)
	}
	if !strings.Contains(failures[0].Error(), "worker/bad_cols") {
		t.Fatalf("failure text = %q", failures[0].Error())
	}
}

func TestRunPreparesEveryQueryAsSubtest(t *testing.T) {
	db := &fakeDB{}
	Run(t, db, map[string]map[string]string{"g": {"q1": "SELECT ?", "q2": "SELECT ?, ?"}})
	Run(t, db, map[string]map[string]string{"g": {"q1": "SELECT ?", "q2": "SELECT ?, ?"}})
	if len(db.prepared) != 4 {
		t.Fatalf("prepared = %v", db.prepared)
	}
}
