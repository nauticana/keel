package schema

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestUsageAttributionAllowsAPIKeyDeletion(t *testing.T) {
	table, err := ParseFile("subscription/usage_ledger.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, fk := range table.ForeignKeys {
		if fk.Name == "usage_ledger_api_key" {
			if fk.OnDelete != "SET NULL" {
				t.Fatalf("usage_ledger_api_key ON DELETE = %q, want SET NULL", fk.OnDelete)
			}
			return
		}
	}
	t.Fatal("usage_ledger_api_key foreign key is missing")
}

func TestAgencyDelegationRoleCodes(t *testing.T) {
	seed, err := ParseSeedFile("seed/agency.yml")
	if err != nil {
		t.Fatal(err)
	}
	var roles []string
	for _, item := range seed.Seeds {
		if item.Table != "constant_value" {
			continue
		}
		for _, row := range item.Rows {
			if len(row) >= 2 && row[0] == "agency_delegation_role" {
				roles = append(roles, row[1].(string))
			}
		}
	}
	slices.Sort(roles)
	want := []string{"operate", "publish", "view"}
	if !slices.Equal(roles, want) {
		t.Fatalf("agency delegation roles = %v, want %v", roles, want)
	}
}

// A user belongs to at most one partner at a time: PostgreSQL enforces it with
// an exclusion constraint, which MySQL cannot express.
func TestPartnerUserPeriodsCannotOverlap(t *testing.T) {
	pg, err := os.ReadFile("basis_pgsql.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CREATE EXTENSION IF NOT EXISTS btree_gist;",
		"CONSTRAINT partner_user_no_overlap EXCLUDE USING gist (user_id WITH =, tsrange(begda, endda) WITH &&)",
	} {
		if !strings.Contains(string(pg), want) {
			t.Errorf("basis_pgsql.sql lacks %q", want)
		}
	}
	my, err := os.ReadFile("basis_mysql.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(my), "EXCLUDE") {
		t.Error("basis_mysql.sql must not carry an exclusion constraint")
	}
	bad := &Schema{Tables: []*Table{{Name: "t", Columns: []*Column{{Name: "a", Type: "INT"}}, PrimaryKey: []string{"a"},
		Exclusions: []*Exclusion{{Name: "x", Using: "gist"}}}}}
	if err := bad.Validate(); err == nil {
		t.Error("an exclusion without an expression must be rejected")
	}
}
