// Package sqlsmoke is test support: it loads schema files into a throwaway
// PostgreSQL and PREPAREs named queries without executing them, so column,
// table, sequence and placeholder drift fails in `go test`.
package sqlsmoke

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/pgsql"
)

// DB is the slice of *pgx.Conn the harness needs.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error)
}

var _ DB = (*pgx.Conn)(nil)

var runID atomic.Uint64

// Failure is one query PostgreSQL refused to prepare.
type Failure struct {
	Group string
	Query string
	Err   error
}

func (f Failure) Error() string { return fmt.Sprintf("%s/%s: %v", f.Group, f.Query, f.Err) }

// LoadSchema executes each SQL file in the order given.
func LoadSchema(ctx context.Context, db DB, files ...string) error {
	for _, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read schema %s: %w", path, err)
		}
		if _, err := db.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("load schema %s: %w", path, err)
		}
	}
	return nil
}

// PrepareAll prepares every query in groups (group name → query name → SQL with
// `?` placeholders) through the production placeholder rewrite and returns the
// ones PostgreSQL rejected, in group/query order.
func PrepareAll(ctx context.Context, db DB, groups map[string]map[string]string) []Failure {
	var failures []Failure
	prefix := runID.Add(1)
	forEachQuery(groups, func(n int, group, name, sql string) {
		if err := prepare(ctx, db, prefix, n, sql); err != nil {
			failures = append(failures, Failure{Group: group, Query: name, Err: err})
		}
	})
	return failures
}

// Run is PrepareAll as one subtest per query, named group/query.
func Run(t *testing.T, db DB, groups map[string]map[string]string) {
	t.Helper()
	prefix := runID.Add(1)
	forEachQuery(groups, func(n int, group, name, sql string) {
		t.Run(group+"/"+name, func(t *testing.T) {
			if err := prepare(context.Background(), db, prefix, n, sql); err != nil {
				t.Fatalf("PREPARE failed: %v", err)
			}
		})
	})
}

func prepare(ctx context.Context, db DB, run uint64, n int, sql string) error {
	_, err := db.Prepare(ctx, fmt.Sprintf("sqlsmoke_%d_%d", run, n), pgsql.RewritePlaceholders(sql))
	return err
}

func forEachQuery(groups map[string]map[string]string, visit func(n int, group, name, sql string)) {
	n := 0
	for _, group := range sortedKeys(groups) {
		for _, name := range sortedKeys(groups[group]) {
			n++
			visit(n, group, name, groups[group][name])
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
