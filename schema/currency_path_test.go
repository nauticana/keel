package schema

import (
	"strings"
	"testing"
)

func moneySchema() *Schema {
	invoice := &Table{Name: "invoice", Columns: []*Column{{Name: "id", Type: "BIGINT"}, {Name: "currency", Type: "CHAR(3)"}}}
	line := &Table{Name: "invoice_line", Columns: []*Column{{Name: "invoice_id", Type: "BIGINT"}, {Name: "amount_minor", Type: "BIGINT"}, {Name: "quantity", Type: "INTEGER"}},
		ForeignKeys: []*ForeignKey{{Name: "invoice_lines", Columns: []string{"invoice_id"}, References: RefTarget{Table: "invoice", Columns: []string{"id"}}}}}
	return &Schema{Tables: []*Table{invoice, line}, tableMap: map[string]*Table{"invoice": invoice, "invoice_line": line}}
}

func TestValidateCurrencyPaths(t *testing.T) {
	for _, tc := range []struct{ table, column, path, wantErr string }{
		{"invoice_line", "amount_minor", "invoice.currency", ""},
		{"invoice_line", "amount_minor", "currency", "has no column currency"},
		{"invoice_line", "amount_minor", "other.currency", "0 foreign keys to other"},
		{"invoice_line", "amount_minor", "invoice.code", "has no column code"},
		{"invoice_line", "quantity", "invoice.currency", "not BIGINT"},
		{"invoice_line", "missing", "currency", "unknown column"},
		{"ledger", "amount_minor", "currency", "unknown table"},
	} {
		seeds := []*SeedFile{{Seeds: []*SeedTable{{Table: "column_display_attribute", Columns: []string{"table_name", "column_name", "currency_path"},
			Rows: [][]any{{tc.table, tc.column, tc.path}, {"invoice", "id", nil}}}}}}
		err := ValidateCurrencyPaths(seeds, moneySchema())
		if tc.wantErr == "" && err != nil {
			t.Errorf("%s.%s %q: %v", tc.table, tc.column, tc.path, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s.%s %q: err = %v, want %q", tc.table, tc.column, tc.path, err, tc.wantErr)
		}
	}
}

// The shipped seeds must load against the shipped schema.
func TestSeedsMatchSchema(t *testing.T) {
	s, err := ParseDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seeds, err := ParseSeedDir("seed")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSeeds(seeds, s); err != nil {
		t.Fatal(err)
	}
	paths := 0
	for _, sf := range seeds {
		for _, st := range sf.Seeds {
			if st.Table == "column_display_attribute" && seedColumn(st, "currency_path") >= 0 {
				paths += len(st.Rows)
			}
		}
	}
	if paths == 0 {
		t.Fatal("no money column is seeded")
	}
}

func TestGenerateSeedSQLKeepsEachBlocksColumns(t *testing.T) {
	seeds := []*SeedFile{{Seeds: []*SeedTable{
		{Table: "column_display_attribute", Columns: []string{"table_name", "column_name", "display_mode"}, Rows: [][]any{{"invoice", "id", "R"}}},
		{Table: "column_display_attribute", Columns: []string{"table_name", "column_name", "currency_path"}, Rows: [][]any{{"invoice_line", "amount_minor", "invoice.currency"}}},
	}}}
	sql := GenerateSeedSQL(seeds, moneySchema())
	for _, want := range []string{
		"INSERT INTO column_display_attribute (table_name, column_name, display_mode) VALUES ('invoice', 'id', 'R')",
		"INSERT INTO column_display_attribute (table_name, column_name, currency_path) VALUES ('invoice_line', 'amount_minor', 'invoice.currency')",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %s in\n%s", want, sql)
		}
	}
}
