package pgsql

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// fakeRows serves a fixed result set so GetPage can run to completion and the
// test can observe both the page statement and the conditional COUNT.
type fakeRows struct {
	cols []string
	rows [][]any
	idx  int
}

func (r *fakeRows) Close()                        {}
func (r *fakeRows) Err() error                    { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }
func (r *fakeRows) Conn() *pgx.Conn               { return nil }
func (r *fakeRows) RawValues() [][]byte           { return nil }
func (r *fakeRows) Values() ([]any, error)        { return r.rows[r.idx-1], nil }

func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription {
	out := make([]pgconn.FieldDescription, len(r.cols))
	for i, c := range r.cols {
		out[i] = pgconn.FieldDescription{Name: c}
	}
	return out
}

func (r *fakeRows) Next() bool {
	if r.idx >= len(r.rows) {
		return false
	}
	r.idx++
	return true
}

func (r *fakeRows) Scan(dest ...any) error {
	row := r.rows[r.idx-1]
	for i := range dest {
		if i >= len(row) {
			break
		}
		if p, ok := dest[i].(*any); ok {
			*p = row[i]
		}
	}
	return nil
}

// countRow returns a scannable single-column row for the COUNT statement.
type countRow struct{ total int64 }

func (c countRow) Scan(dest ...any) error {
	if p, ok := dest[0].(*int64); ok {
		*p = c.total
	}
	return nil
}

// pageQuerier records every statement in order and answers SELECTs with a
// configured page of rows plus a configured COUNT total.
type pageQuerier struct {
	statements []string
	args       [][]any
	pageRows   [][]any
	total      int64
}

func (q *pageQuerier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	q.record(sql, args)
	return pgconn.CommandTag{}, nil
}

func (q *pageQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.record(sql, args)
	return &fakeRows{cols: []string{"id", "partner_id", "amount"}, rows: q.pageRows}, nil
}

func (q *pageQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.record(sql, args)
	return countRow{total: q.total}
}

func (q *pageQuerier) record(sql string, args []any) {
	q.statements = append(q.statements, sql)
	q.args = append(q.args, args)
}

func newPagedService(t *testing.T, table *model.TableDefinition, q *pageQuerier) *TableServicePgsql {
	t.Helper()
	s := &TableServicePgsql{
		AbstractTableService: data.AbstractTableService{
			Table:     table,
			AuthQuery: &stubAuthQuery{permRows: wildcardSelectGrant()},
		},
		Client: q,
		Schema: "public",
	}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s
}

func row(id int64) []any { return []any{id, int64(42), "10.00"} }

// TestGetPage_PushesBoundsAndCountsUnpagedTotal is the core KR-006 regression:
// the page bounds must reach SQL rather than being sliced after a full read,
// and the reported total must come from a COUNT over the same scoped WHERE.
func TestGetPage_PushesBoundsAndCountsUnpagedTotal(t *testing.T) {
	q := &pageQuerier{pageRows: [][]any{row(1), row(2)}, total: 57}
	s := newPagedService(t, partnerSpecificTable(), q)

	items, total, err := s.GetPage(context.Background(), 42, 7, nil,
		port.PageRequest{Limit: 2, Offset: 10})
	if err != nil {
		t.Fatalf("GetPage: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	if total != 57 {
		t.Fatalf("total = %d, want the COUNT result 57", total)
	}
	if len(q.statements) != 2 {
		t.Fatalf("statements = %#v, want page + count", q.statements)
	}
	page := q.statements[0]
	if !strings.Contains(page, "LIMIT $2") || !strings.Contains(page, "OFFSET $3") {
		t.Errorf("page statement lacks pushed-down bounds: %s", page)
	}
	if got := q.args[0]; len(got) != 3 || got[1] != 2 || got[2] != 10 {
		t.Errorf("page args = %v, want [partner, limit, offset]", got)
	}
	count := q.statements[1]
	if !strings.HasPrefix(count, `SELECT count(*) FROM "public"."sales_order"`) {
		t.Errorf("count statement = %s", count)
	}
	// The count must be scoped by the same WHERE — otherwise the total leaks
	// the size of other partners' data.
	if !strings.Contains(count, `WHERE "partner_id" = $1`) {
		t.Errorf("count statement is not partner-scoped: %s", count)
	}
	if got := q.args[1]; len(got) != 1 || got[0] != int64(42) {
		t.Errorf("count args = %v, want the scoped partner only", got)
	}
}

// TestGetPage_AppendsPrimaryKeyForStableOrder covers the paging-correctness
// half of KR-006: without a total order, rows tied on the caller's column can
// repeat or vanish as the client walks offsets.
func TestGetPage_AppendsPrimaryKeyForStableOrder(t *testing.T) {
	q := &pageQuerier{pageRows: [][]any{row(1)}, total: 1}
	s := newPagedService(t, partnerSpecificTable(), q)

	if _, _, err := s.GetPage(context.Background(), 42, 7, nil,
		port.PageRequest{Limit: 5, OrderBy: "amount DESC"}); err != nil {
		t.Fatalf("GetPage: %v", err)
	}
	if want := `ORDER BY "amount" DESC, "id"`; !strings.Contains(q.statements[0], want) {
		t.Fatalf("statement %q does not contain %q", q.statements[0], want)
	}
}

// TestGetPage_ShortFirstPageSkipsCount — a first page that didn't fill is the
// whole result set, so the extra round trip is pure waste.
func TestGetPage_ShortFirstPageSkipsCount(t *testing.T) {
	q := &pageQuerier{pageRows: [][]any{row(1), row(2)}, total: 999}
	s := newPagedService(t, partnerSpecificTable(), q)

	_, total, err := s.GetPage(context.Background(), 42, 7, nil, port.PageRequest{Limit: 10})
	if err != nil {
		t.Fatalf("GetPage: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2 from the short page", total)
	}
	if len(q.statements) != 1 {
		t.Fatalf("statements = %#v, want the page query only", q.statements)
	}
}

// TestGetPage_ByKeyPathSkipsBounds — an all-primary-key filter matches at most
// one row, so LIMIT/OFFSET and a COUNT would only add work.
func TestGetPage_ByKeyPathSkipsBounds(t *testing.T) {
	q := &pageQuerier{pageRows: [][]any{row(1)}, total: 1}
	s := newPagedService(t, userAccountTable(false), q)

	_, total, err := s.GetPage(context.Background(), 42, 7,
		map[string]any{"id": int64(1)}, port.PageRequest{Limit: 10})
	if err != nil {
		t.Fatalf("GetPage: %v", err)
	}
	if total != 1 {
		t.Fatalf("total = %d, want 1", total)
	}
	if len(q.statements) != 1 || strings.Contains(q.statements[0], "LIMIT") {
		t.Fatalf("statements = %#v, want a single unbounded by-key select", q.statements)
	}
}

// TestGetPage_InheritsPartnerScopeCoercion proves the paged path did not fork
// away from the KR-001 scoping rules: a foreign ?partner_id is still coerced.
func TestGetPage_InheritsPartnerScopeCoercion(t *testing.T) {
	q := &pageQuerier{pageRows: nil, total: 0}
	s := newPagedService(t, partnerSpecificTable(), q)

	if _, _, err := s.GetPage(context.Background(), 42, 7,
		map[string]any{"partner_id": int64(999)}, port.PageRequest{Limit: 5}); err != nil {
		t.Fatalf("GetPage: %v", err)
	}
	if got := q.args[0]; len(got) == 0 || got[0] != int64(42) {
		t.Fatalf("page args = %v, want partner coerced to the session partner", got)
	}
}

// TestOrderTerms_RejectionIsClientError — a bad ?order= is malformed caller
// input, not a server fault. At 500 the handler sanitizes the body (the client
// never learns which column was rejected) and journals every typo as an
// operator-facing error.
func TestOrderTerms_RejectionIsClientError(t *testing.T) {
	s := newPagedService(t, partnerSpecificTable(), &pageQuerier{})
	for _, in := range []string{"nope", "amount SIDEWAYS", "amount DESC id"} {
		_, err := s.orderTerms(in)
		var appErr *model.AppError
		if !errors.As(err, &appErr) {
			t.Fatalf("orderTerms(%q) = %v, want a typed *model.AppError", in, err)
		}
		if appErr.Status != http.StatusBadRequest {
			t.Errorf("orderTerms(%q) status = %d, want 400", in, appErr.Status)
		}
	}
}

func TestPlanSelect_UnknownFilterColumnIsClientError(t *testing.T) {
	s := newPagedService(t, partnerSpecificTable(), &pageQuerier{})
	_, err := s.planSelect(context.Background(), 42, 7, map[string]any{"nope": 1})
	var appErr *model.AppError
	if !errors.As(err, &appErr) || appErr.Status != http.StatusBadRequest {
		t.Fatalf("planSelect with unknown filter column = %v, want a 400 AppError", err)
	}
}

func TestOrderTerms(t *testing.T) {
	s := newPagedService(t, partnerSpecificTable(), &pageQuerier{})
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ""},
		{in: "amount", want: ` ORDER BY "amount"`},
		{in: "amount DESC", want: ` ORDER BY "amount" DESC`},
		{in: "Amount desc", want: ` ORDER BY "amount" DESC`},
		// Comma-separated terms previously collapsed to `ORDER BY amount id`,
		// which PostgreSQL rejects outright.
		{in: "amount DESC, id", want: ` ORDER BY "amount" DESC, "id"`},
		{in: "nope", wantErr: true},
		{in: "amount SIDEWAYS", wantErr: true},
		{in: "amount DESC id", wantErr: true},
	}
	for _, c := range cases {
		terms, err := s.orderTerms(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("orderTerms(%q) = %v, want error", c.in, terms)
			}
			continue
		}
		if err != nil {
			t.Errorf("orderTerms(%q): %v", c.in, err)
			continue
		}
		if got := orderSQL(terms); got != c.want {
			t.Errorf("orderTerms(%q) → %q, want %q", c.in, got, c.want)
		}
	}
}
