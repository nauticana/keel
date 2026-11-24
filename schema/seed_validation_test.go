package schema

import (
	"fmt"
	"strings"
	"testing"
)

func TestSeedsSatisfyForeignKeys(t *testing.T) {
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
}

func TestValidateSeedsRejectsMissingParent(t *testing.T) {
	s, err := ParseDir("core")
	if err != nil {
		t.Fatal(err)
	}
	seeds := []*SeedFile{{Seeds: []*SeedTable{
		{Table: "rest_api_header", Columns: []string{"id", "master_table"}, Rows: [][]any{{"thing", "thing"}}},
		{Table: "rest_api_child", Columns: []string{"api_id", "seq", "parent_seq", "constraint_name"}, Rows: [][]any{{"thing", 1, 0, "thing_children"}}},
	}}}
	if err := ValidateSeeds(seeds, s); err == nil {
		t.Fatal("child without its foreign_key_lookup accepted")
	}
}

func TestValidateRejectsLongSequenceName(t *testing.T) {
	s, err := ParseDir("core")
	if err != nil {
		t.Fatal(err)
	}
	s.GetTable("consent_event").Sequence.Name = "consent_event_sequence_name_too_long"
	if err := s.Validate(); err == nil {
		t.Fatal("sequence name over 32 characters accepted")
	}
}

func TestParseSeedPathAcceptsFilesAndDirectories(t *testing.T) {
	file, err := ParseSeedPath("seed/core.yml")
	if err != nil || len(file) != 1 {
		t.Fatalf("seed file = %d files, %v", len(file), err)
	}
	dir, err := ParseSeedPath("seed")
	if err != nil || len(dir) < 2 {
		t.Fatalf("seed directory = %d files, %v", len(dir), err)
	}
	if _, err := ParseSeedPath("seed.go"); err == nil {
		t.Fatal("non-YAML seed file accepted")
	}
	if _, err := ParseSeedPath("seed/missing.yml"); err == nil {
		t.Fatal("missing seed file accepted")
	}
}

// user_account.status changes only through the account status actions, so
// generic update must skip it.
func TestAccountStatusIsInsertOnly(t *testing.T) {
	seeds, err := ParseSeedDir("seed")
	if err != nil {
		t.Fatal(err)
	}
	for _, sf := range seeds {
		for _, st := range sf.Seeds {
			table, column, mode := seedColumn(st, "table_name"), seedColumn(st, "column_name"), seedColumn(st, "display_mode")
			if st.Table != "column_display_attribute" || table < 0 || column < 0 || mode < 0 {
				continue
			}
			for _, r := range st.Rows {
				if r[table] == "user_account" && r[column] == "status" && r[mode] == "I" {
					return
				}
			}
		}
	}
	t.Fatal("no column_display_attribute row makes user_account.status insert-only")
}

func seededRows(t *testing.T, table string) [][]any {
	t.Helper()
	seeds, err := ParseSeedDir("seed")
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]any
	for _, sf := range seeds {
		for _, st := range sf.Seeds {
			if st.Table == table {
				rows = append(rows, st.Rows...)
			}
		}
	}
	return rows
}

func TestSeededGrantsOfPlatformRoles(t *testing.T) {
	grants := map[string]bool{}
	for _, r := range seededRows(t, "authorization_role_permission") {
		grants[fmt.Sprint(r...)] = true
		if r[0] == "APP_ADMIN" && (r[1] == "USER_ACCOUNT" || r[1] == "BUSINESS_PARTNER" || strings.Contains(fmt.Sprint(r[3]), "partner_user") ||
			r[3] == "business_partner" || r[3] == "partner_plan_subscription") {
			t.Errorf("APP_ADMIN holds the business grant %v", r)
		}
	}
	for _, a := range seededRows(t, "authorization_object_action") {
		if !grants[fmt.Sprint("SUPER", a[0], a[1], "*")] {
			t.Errorf("SUPER lacks %v/%v", a[0], a[1])
		}
	}
	for _, want := range [][]any{{"BUSINESS_ADMIN", "BUSINESS_PARTNER", "CREATE", "business_partner"}, {"SECURITY_ADMIN", "USER_ACCOUNT", "LOCK", "user_account"}} {
		if !grants[fmt.Sprint(want...)] {
			t.Errorf("missing grant %v", want)
		}
	}
}

func TestSeededGlobalRoles(t *testing.T) {
	var global []string
	for _, r := range seededRows(t, "authorization_role") {
		if r[3] == true {
			global = append(global, fmt.Sprint(r[0]))
			if r[2] == true {
				t.Errorf("%v is both partner-scoped and global", r[0])
			}
		}
	}
	if got := strings.Join(global, " "); got != "SUPER APP_ADMIN SECURITY_ADMIN SECURITY_OPER BUSINESS_ADMIN" {
		t.Fatalf("global roles = %q", got)
	}
}
