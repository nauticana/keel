package pgsql

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/port"
)

type stubRows struct {
	pgx.Rows
	left   int
	err    error
	closed bool
}

func (r *stubRows) Next() bool        { r.left--; return r.left >= 0 }
func (r *stubRows) Scan(...any) error { return nil }
func (r *stubRows) Err() error        { return r.err }
func (r *stubRows) Close()            { r.closed = true }

type stubConn struct {
	rows *stubRows
	err  error
}

func (c stubConn) Query(context.Context, string, ...any) (pgx.Rows, error) { return c.rows, c.err }
func (c stubConn) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
func (c stubConn) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func TestNamedQueryEach(t *testing.T) {
	ctx := context.Background()
	queries := map[string]string{"q": "SELECT 1"}
	count := func(n *int) func(port.RowScanner) error { return func(port.RowScanner) error { *n++; return nil } }

	rows := &stubRows{left: 3}
	n := 0
	if err := (namedQuery{stubConn{rows: rows}, queries}).each(ctx, "q", count(&n), nil); err != nil || n != 3 || !rows.closed {
		t.Fatalf("err=%v rows=%d closed=%v", err, n, rows.closed)
	}

	boom := errors.New("boom")
	rows = &stubRows{left: 3}
	if err := (namedQuery{stubConn{rows: rows}, queries}).each(ctx, "q", func(port.RowScanner) error { return boom }, nil); !errors.Is(err, boom) || !rows.closed {
		t.Errorf("scan error: %v closed=%v", err, rows.closed)
	}
	if err := (namedQuery{stubConn{rows: &stubRows{err: boom}}, queries}).each(ctx, "q", count(&n), nil); !errors.Is(err, boom) {
		t.Errorf("iteration error: %v", err)
	}
	if err := (namedQuery{stubConn{err: boom}, queries}).each(ctx, "q", count(&n), nil); !errors.Is(err, boom) {
		t.Errorf("query error: %v", err)
	}
	if err := (namedQuery{stubConn{}, queries}).each(ctx, "missing", count(&n), nil); err == nil {
		t.Error("unknown query name accepted")
	}
}
