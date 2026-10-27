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

// fkRow is one (constraint, child, position, child column, parent, parent column) catalog row.
func fkRow(constraint, child string, position int, column, parent, parentColumn string) []any {
	return []any{constraint, child, int64(position), column, parent, parentColumn}
}

// fkResult adds the columns rows name to tables that lack them.
func fkResult(tables map[string]*model.TableDefinition, rows ...[]any) *model.QueryResult {
	for _, row := range rows {
		for _, ref := range [][2]string{{row[1].(string), row[3].(string)}, {row[4].(string), row[5].(string)}} {
			if t := tables[ref[0]]; t != nil && t.Column(ref[1]) == nil {
				t.Columns = append(t.Columns, &model.TableColumn{ColumnName: ref[1]})
			}
		}
	}
	return &model.QueryResult{Rows: rows}
}

func TestLoadForeignKeysPartnerScopeThroughCompositeKeys(t *testing.T) {
	repo := &AbstractRepository{TableDefinitions: fkTables(
		"business_partner", "partner_domain", "partner_domain_verification",
		"verification_note", "site_page", "agency_profile", "agency_note", "stray", "stray_child",
	)}
	res := fkResult(repo.TableDefinitions,
		fkRow("agency_note_profile", "agency_note", 1, "partner_id", "agency_profile", "partner_id"),
		fkRow("agency_profile_partner", "agency_profile", 1, "agency_partner_id", "business_partner", "partner_id"),
		fkRow("note_verification", "verification_note", 1, "domain_url", "partner_domain_verification", "domain_url"),
		fkRow("note_verification", "verification_note", 2, "partner_id", "partner_domain_verification", "partner_id"),
		fkRow("note_verification", "verification_note", 3, "verified_at", "partner_domain_verification", "verified_at"),
		fkRow("partner_domain_verifications", "partner_domain_verification", 1, "partner_id", "partner_domain", "partner_id"),
		fkRow("partner_domain_verifications", "partner_domain_verification", 2, "domain_url", "partner_domain", "domain_url"),
		fkRow("partner_domains", "partner_domain", 1, "partner_id", "business_partner", "partner_id"),
		fkRow("site_page_domain", "site_page", 1, "partner_id", "partner_domain", "partner_id"),
		fkRow("site_page_domain", "site_page", 2, "domain_url", "partner_domain", "domain_url"),
		fkRow("stray_child_parent", "stray_child", 1, "partner_id", "stray", "partner_id"),
	)
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
	res := fkResult(repo.TableDefinitions,
		fkRow("a_tenant", "a", 1, "partner_id", "tenant", "partner_id"),
		fkRow("b_partner", "b", 1, "partner_id", "business_partner", "partner_id"),
	)
	if err := repo.LoadForeignKeys(context.Background(), res, nil); err != nil {
		t.Fatal(err)
	}
	if !repo.TableDefinitions["a"].PartnerSpecific || repo.TableDefinitions["b"].PartnerSpecific {
		t.Error("only the configured partner table roots partner scope")
	}
}

func TestLoadForeignKeysPairsReferencedColumns(t *testing.T) {
	repo := &AbstractRepository{TableDefinitions: fkTables("provider", "oidc")}
	res := fkResult(repo.TableDefinitions,
		fkRow("provider_oidc", "oidc", 1, "partner_id", "provider", "partner_id"),
		fkRow("provider_oidc", "oidc", 2, "provider_id", "provider", "id"),
	)
	if err := repo.LoadForeignKeys(context.Background(), res, nil); err != nil {
		t.Fatal(err)
	}
	fk := repo.ForeignKeys["provider_oidc"]
	if len(fk.ParentColumns) != 2 || fk.ParentColumns[0].ColumnName != "partner_id" || fk.ParentColumns[1].ColumnName != "id" {
		t.Errorf("ParentColumns = %v", fk.ParentColumns)
	}

	repo = &AbstractRepository{TableDefinitions: fkTables("provider", "oidc")}
	res = fkResult(repo.TableDefinitions, fkRow("provider_oidc", "oidc", 1, "provider_id", "provider", "id"))
	res.Rows[0][5] = "missing"
	if err := repo.LoadForeignKeys(context.Background(), res, nil); err == nil {
		t.Error("a foreign key to an unknown parent column must fail")
	}
}

func TestLoadForeignKeysRefusesUnknownChildColumn(t *testing.T) {
	repo := &AbstractRepository{TableDefinitions: fkTables("provider", "oidc")}
	repo.TableDefinitions["provider"].Columns = []*model.TableColumn{{ColumnName: "id"}}
	res := &model.QueryResult{Rows: [][]any{fkRow("provider_oidc", "oidc", 1, "provider_id", "provider", "id")}}
	if err := repo.LoadForeignKeys(context.Background(), res, nil); err == nil {
		t.Error("a foreign key whose child column is unknown must fail")
	}
}
