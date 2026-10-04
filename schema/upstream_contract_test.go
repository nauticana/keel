package schema

import (
	"slices"
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
