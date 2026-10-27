package data

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// displayRows answers the column display query with fixed rows.
type displayRows struct {
	port.QueryService
	rows [][]any
	err  error
}

func (d displayRows) Query(context.Context, string, ...any) (*model.QueryResult, error) {
	return &model.QueryResult{Rows: d.rows}, d.err
}

func displayRow(table, column, path string) []any {
	return []any{table, column, nil, nil, nil, path}
}

func moneyRepo(t *testing.T, rows ...[]any) (*AbstractRepository, error) {
	t.Helper()
	col := func(name, dataType string) *model.TableColumn {
		return &model.TableColumn{ColumnName: name, DataType: dataType}
	}
	repo := &AbstractRepository{TableDefinitions: map[string]*model.TableDefinition{
		"invoice":      {TableName: "invoice", Columns: []*model.TableColumn{col("id", model.DT_BIGINT), col("currency", model.DT_STRING)}},
		"invoice_line": {TableName: "invoice_line", Columns: []*model.TableColumn{col("invoice_id", model.DT_BIGINT), col("amount_minor", model.DT_BIGINT), col("note", model.DT_STRING)}},
		"allocation":   {TableName: "allocation", Columns: []*model.TableColumn{col("line_id", model.DT_BIGINT), col("amount_minor", model.DT_BIGINT)}},
		"transfer":     {TableName: "transfer", Columns: []*model.TableColumn{col("from_id", model.DT_BIGINT), col("to_id", model.DT_BIGINT), col("amount_minor", model.DT_BIGINT)}},
	}}
	fks := fkResult(repo.TableDefinitions,
		fkRow("invoice_lines", "invoice_line", 1, "invoice_id", "invoice", "id"),
		fkRow("line_allocations", "allocation", 1, "line_id", "invoice_line", "id"),
		fkRow("transfer_from", "transfer", 1, "from_id", "invoice", "id"),
		fkRow("transfer_to", "transfer", 1, "to_id", "invoice", "id"),
	)
	if err := repo.LoadForeignKeys(context.Background(), fks, nil); err != nil {
		t.Fatal(err)
	}
	repo.QuerySvc = displayRows{rows: rows}
	return repo, repo.applyColumnDisplay(context.Background())
}

func TestApplyColumnDisplayResolvesCurrencyPaths(t *testing.T) {
	repo, err := moneyRepo(t,
		displayRow("invoice_line", "amount_minor", "invoice.currency"),
		displayRow("allocation", "amount_minor", "invoice_line.invoice.currency"),
		displayRow("invoice", "id", ""),
		displayRow("unknown", "x", "currency"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := repo.TableDefinitions["allocation"].Column("amount_minor").CurrencyPath; got != "invoice_line.invoice.currency" {
		t.Fatalf("CurrencyPath = %q", got)
	}
	if got := repo.TableDefinitions["invoice"].Column("id").CurrencyPath; got != "" {
		t.Fatalf("a row without a path sets %q", got)
	}
}

func TestApplyColumnDisplayRefusesBadCurrencyPaths(t *testing.T) {
	for _, tc := range []struct{ table, column, path, wantErr string }{
		{"invoice_line", "amount_minor", "currency", "has no column currency"},
		{"invoice_line", "amount_minor", "allocation.currency", "no foreign key to allocation"},
		{"invoice_line", "amount_minor", "invoice.code", "has no column code"},
		{"invoice_line", "note", "invoice.currency", "not bigint"},
		{"transfer", "amount_minor", "invoice.currency", "more than one foreign key to invoice"},
	} {
		_, err := moneyRepo(t, displayRow(tc.table, tc.column, tc.path))
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s %q: err = %v, want %q", tc.column, tc.path, err, tc.wantErr)
		}
	}
}

func TestApplyColumnDisplayReturnsQueryError(t *testing.T) {
	repo := &AbstractRepository{QuerySvc: displayRows{err: errors.New("relation missing")}}
	if err := repo.applyColumnDisplay(context.Background()); err == nil || !strings.Contains(err.Error(), "relation missing") {
		t.Fatalf("err = %v", err)
	}
}
