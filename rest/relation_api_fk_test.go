package rest

import (
	"context"
	"testing"

	"github.com/nauticana/keel/model"
)

type whereTableService struct {
	legacyTableService
	where map[string]any
}

func (s *whereTableService) Get(_ context.Context, _ int64, _ int, where map[string]any, _ string) ([]any, error) {
	s.where = where
	return s.rows, nil
}

// A child keyed by (partner_id, provider_id) references the parent's unique
// (partner_id, id), not its primary key id.
func uniqueKeyRelation() (*RelationAPI, *whereTableService) {
	col := func(name, pascal string) *model.TableColumn {
		return &model.TableColumn{ColumnName: name, PascalName: pascal}
	}
	id, partner := col("id", "Id"), col("partner_id", "PartnerId")
	parent := &model.TableDefinition{TableName: "provider", Columns: []*model.TableColumn{id, partner}, Keys: []*model.TableColumn{id}}
	childPartner, childProvider := col("partner_id", "PartnerId"), col("provider_id", "ProviderId")
	child := &model.TableDefinition{TableName: "oidc", Columns: []*model.TableColumn{childPartner, childProvider}, Keys: []*model.TableColumn{childPartner, childProvider}}
	fk := &model.ForeignKey{Parent: parent, Child: child, PascalName: "ProviderOidc", ConstraintName: "provider_oidc",
		ParentColumns: []*model.TableColumn{partner, id}, ChildColumns: []*model.TableColumn{childPartner, childProvider}}
	parent.Children = []*model.ForeignKey{fk}

	childSvc := &whereTableService{legacyTableService: legacyTableService{table: child}}
	api := &RelationAPI{
		DataService:   &legacyTableService{table: parent, rows: []any{map[string]any{"Id": int64(42), "PartnerId": int64(7)}}},
		ChildServices: map[string]RelationAPI{"ProviderOidc": {DataService: childSvc, ParentRelation: fk}},
	}
	return api, childSvc
}

func TestRelationPairsUniqueKeyColumns(t *testing.T) {
	api, childSvc := uniqueKeyRelation()
	if _, err := api.Get(context.Background(), 7, 1, nil, ""); err != nil {
		t.Fatal(err)
	}
	if childSvc.where["partner_id"] != int64(7) || childSvc.where["provider_id"] != int64(42) || len(childSvc.where) != 2 {
		t.Errorf("child filter = %v, want partner_id 7 and provider_id 42", childSvc.where)
	}

	child := map[string]any{"Issuer": "https://idp"}
	api.propogateKeys(map[string]any{"Id": int64(42), "PartnerId": int64(7), "ProviderOidc": []any{child}})
	if child["PartnerId"] != int64(7) || child["ProviderId"] != int64(42) {
		t.Errorf("propagated child = %v", child)
	}

	rel := api.ChildServices["ProviderOidc"]
	def := rel.GetDefinition("provider", "v1")
	parentKeys, childKeys := def["ParentKeys"].([]*model.TableColumn), def["ChildKeys"].([]*model.TableColumn)
	if len(parentKeys) != 2 || parentKeys[0].ColumnName != "partner_id" || parentKeys[1].ColumnName != "id" ||
		childKeys[0].ColumnName != "partner_id" || childKeys[1].ColumnName != "provider_id" {
		t.Errorf("ParentKeys %v must pair with ChildKeys %v by index", parentKeys, childKeys)
	}
}
