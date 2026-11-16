package schema

import (
	"strings"
	"testing"
)

func TestValidateActionParametersRejectsKeyColumnAndDuplicate(t *testing.T) {
	s, err := ParseDir(".")
	if err != nil {
		t.Fatal(err)
	}
	params := func(rows ...[]any) []*SeedFile {
		return []*SeedFile{{Seeds: []*SeedTable{{
			Table:   "table_action_parameter",
			Columns: []string{"table_name", "action_name", "seq", "param_name", "caption", "data_type", "required"},
			Rows:    rows,
		}}}}
	}
	if err := ValidateActionParameters(params(
		[]any{"partner_identity_provider", "configure", 1, "connection_id", "Connection", "bigint", false},
	), s); err != nil {
		t.Fatalf("distinct parameter rejected: %v", err)
	}
	err = ValidateActionParameters(params(
		[]any{"partner_identity_provider", "configure", 1, "id", "Connection", "bigint", false},
		[]any{"partner_identity_provider", "configure", 2, "caption", "Caption", "string", true},
		[]any{"partner_identity_provider", "configure", 3, "caption", "Caption", "string", true},
	), s)
	if err == nil || !strings.Contains(err.Error(), "configure.id is named like a key column") || !strings.Contains(err.Error(), "configure.caption is declared twice") {
		t.Fatalf("err = %v, want the key-column and duplicate parameters", err)
	}
}
