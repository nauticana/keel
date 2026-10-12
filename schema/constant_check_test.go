package schema

import (
	"strings"
	"testing"
)

func constantSeeds(check string) ([]*SeedFile, *Schema) {
	thing := &Table{Name: "thing", Columns: []*Column{{Name: "status", Type: "CHAR(1)"}}}
	if check != "" {
		thing.Checks = []*Check{{Name: "chk_thing_status", Expression: check}}
	}
	s := &Schema{Tables: []*Table{thing}, tableMap: map[string]*Table{"thing": thing}}
	seeds := []*SeedFile{{Seeds: []*SeedTable{
		{Table: "constant_value", Columns: []string{"constant_id", "value", "caption"}, Rows: [][]any{{"thing_status", "A", "Active"}, {"thing_status", "X", "Closed"}}},
		{Table: "constant_lookup", Columns: []string{"constant_id", "table_name", "column_name"}, Rows: [][]any{{"thing_status", "thing", "status"}}},
	}}}
	return seeds, s
}

func TestValidateConstantChecks(t *testing.T) {
	for check, wantErr := range map[string]string{
		"status IN ('A', 'X')":      "",
		"status IN ('X', 'A')":      "",
		"":                          "has no CHECK",
		"status IN ('A')":           "CHECK lists [A]",
		"status IN ('A', 'X', 'Z')": "CHECK lists [A X Z]",
	} {
		seeds, s := constantSeeds(check)
		err := ValidateConstantChecks(seeds, s)
		if wantErr == "" && err != nil {
			t.Errorf("%q: %v", check, err)
		}
		if wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)) {
			t.Errorf("%q: err = %v, want %q", check, err, wantErr)
		}
	}
}

func TestValidateConstantChecksRequiresCodes(t *testing.T) {
	seeds, s := constantSeeds("status IN ('A', 'X')")
	seeds[0].Seeds = seeds[0].Seeds[1:]
	if err := ValidateConstantChecks(seeds, s); err == nil || !strings.Contains(err.Error(), "no constant_value rows") {
		t.Fatalf("err = %v", err)
	}
}
