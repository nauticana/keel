package data

import (
	"context"
	"testing"

	"github.com/nauticana/keel/model"
)

func fkTables(names ...string) map[string]*model.TableDefinition {
	tables := make(map[string]*model.TableDefinition, len(names))
	for _, name := range names {
		tables[name] = &model.TableDefinition{TableName: name}
	}
	return tables
}

// fkRow is one (constraint, child, position, child column, parent) catalog row.
func fkRow(constraint, child string, position int, column, parent string) []any {
	return []any{constraint, child, int64(position), column, parent}
}

func TestLoadForeignKeysPartnerScopeThroughCompositeKeys(t *testing.T) {
	repo := &AbstractRepository{TableDefinitions: fkTables(
		"business_partner", "partner_domain", "partner_domain_verification",
		"verification_note", "site_page", "agency_profile", "agency_note", "stray", "stray_child",
	)}
	res := &model.QueryResult{Rows: [][]any{
		fkRow("agency_note_profile", "agency_note", 1, "partner_id", "agency_profile"),
		fkRow("agency_profile_partner", "agency_profile", 1, "agency_partner_id", "business_partner"),
		fkRow("note_verification", "verification_note", 1, "domain_url", "partner_domain_verification"),
		fkRow("note_verification", "verification_note", 2, "partner_id", "partner_domain_verification"),
		fkRow("note_verification", "verification_note", 3, "verified_at", "partner_domain_verification"),
		fkRow("partner_domain_verifications", "partner_domain_verification", 1, "partner_id", "partner_domain"),
		fkRow("partner_domain_verifications", "partner_domain_verification", 2, "domain_url", "partner_domain"),
		fkRow("partner_domains", "partner_domain", 1, "partner_id", "business_partner"),
		fkRow("site_page_domain", "site_page", 1, "partner_id", "partner_domain"),
		fkRow("site_page_domain", "site_page", 2, "domain_url", "partner_domain"),
		fkRow("stray_child_parent", "stray_child", 1, "partner_id", "stray"),
	}}
	if err := repo.LoadForeignKeys(context.Background(), res, nil); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"partner_domain":              true,
		"partner_domain_verification": true,
		"verification_note":           true, // two levels down, partner_id second in the key
		"site_page":                   true,
		"agency_profile":              false, // references the partner through agency_partner_id
		"agency_note":                 false, // its parent is not partner-specific
		"stray_child":                 false,
		"business_partner":            false,
	}
	for name, specific := range want {
		if got := repo.TableDefinitions[name].PartnerSpecific; got != specific {
			t.Errorf("%s.PartnerSpecific = %v, want %v", name, got, specific)
		}
	}
}

func TestLoadForeignKeysHonorsPartnerTableName(t *testing.T) {
	repo := &AbstractRepository{PartnerTableName: "tenant", TableDefinitions: fkTables("tenant", "business_partner", "a", "b")}
	res := &model.QueryResult{Rows: [][]any{
		fkRow("a_tenant", "a", 1, "partner_id", "tenant"),
		fkRow("b_partner", "b", 1, "partner_id", "business_partner"),
	}}
	if err := repo.LoadForeignKeys(context.Background(), res, nil); err != nil {
		t.Fatal(err)
	}
	if !repo.TableDefinitions["a"].PartnerSpecific || repo.TableDefinitions["b"].PartnerSpecific {
		t.Error("only the configured partner table roots partner scope")
	}
}
