package pgsql

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
)

func patchTable() *model.TableDefinition {
	idCol := &model.TableColumn{ColumnName: "id", PascalName: "Id", IsKey: true}
	return &model.TableDefinition{
		TableName: "invoice",
		Columns: []*model.TableColumn{
			idCol,
			{ColumnName: "partner_id", PascalName: "PartnerId"},
			{ColumnName: "amount", PascalName: "Amount", DataType: model.DT_INT},
			{ColumnName: "note", PascalName: "Note", DataType: model.DT_STRING},
			{ColumnName: "status", PascalName: "Status", DataType: model.DT_STRING, DisplayMode: model.DisplayReadonly},
			{ColumnName: "updated_at", PascalName: "UpdatedAt", DataType: model.DT_TIME, DisplayMode: model.DisplayUpdateStamp},
			{ColumnName: "updated_by", PascalName: "UpdatedBy", DataType: model.DT_INT, DisplayMode: model.DisplayUpdateStamp},
		},
		Keys:            []*model.TableColumn{idCol},
		PartnerSpecific: true,
	}
}

func TestPatch_WritesOnlyListedColumnsPlusStamps(t *testing.T) {
	auth := &stubAuthQuery{permRows: wildcardSelectGrant(), globalRows: nil}
	s, qc := newService(t, patchTable(), auth)

	err := s.Patch(context.Background(), 42, 7, map[string]any{"id": int64(1)}, map[string]any{"amount": int64(5)})
	if !errors.Is(err, errSentinel) {
		t.Fatalf("Patch returned %v, want sentinel", err)
	}
	want := `UPDATE "public"."invoice" SET "amount" = $1, "updated_at" = now(), "updated_by" = $2 WHERE "id" = $3 AND "partner_id" = $4`
	if qc.sql != want {
		t.Fatalf("sql\n got %s\nwant %s", qc.sql, want)
	}
	if len(qc.args) != 4 || qc.args[0] != int64(5) || qc.args[1] != 7 || qc.args[2] != int64(1) || qc.args[3] != int64(42) {
		t.Fatalf("args = %v", qc.args)
	}
	if strings.Contains(qc.sql, `"note"`) {
		t.Fatal("unlisted column must not be touched")
	}
}

func TestPatch_RejectsBadInput(t *testing.T) {
	auth := &stubAuthQuery{permRows: wildcardSelectGrant(), globalRows: nil}
	s, qc := newService(t, patchTable(), auth)
	ctx := context.Background()
	key := map[string]any{"Id": int64(1)}

	cases := map[string]struct {
		key, changes map[string]any
	}{
		"readonly column": {key, map[string]any{"status": "X"}},
		"scope column":    {key, map[string]any{"partner_id": int64(9)}},
		"key column":      {key, map[string]any{"id": int64(9)}},
		"unknown column":  {key, map[string]any{"nope": 1}},
		"empty changes":   {key, map[string]any{}},
		"missing key":     {map[string]any{}, map[string]any{"amount": int64(1)}},
		"surplus key":     {map[string]any{"id": int64(1), "nope": 2}, map[string]any{"amount": int64(1)}},
	}
	for name, c := range cases {
		qc.sql = ""
		err := s.Patch(ctx, 42, 7, c.key, c.changes)
		if err == nil || errors.Is(err, errSentinel) {
			t.Errorf("%s: err = %v, want validation error", name, err)
		}
		if qc.sql != "" {
			t.Errorf("%s: must not reach the database: %s", name, qc.sql)
		}
	}
}

func TestPatch_Forbidden(t *testing.T) {
	auth := &stubAuthQuery{permRows: nil, globalRows: nil}
	s, _ := newService(t, patchTable(), auth)
	err := s.Patch(context.Background(), 42, 7, map[string]any{"id": int64(1)}, map[string]any{"amount": int64(5)})
	var appErr *model.AppError
	if !errors.As(err, &appErr) || appErr.Status != 403 {
		t.Fatalf("err = %v, want 403 AppError", err)
	}
}

func TestPatch_PartnerUserScopedGuardsMembership(t *testing.T) {
	table := patchTable()
	table.TableName = "user_account"
	table.PartnerSpecific = false
	table.PartnerUserScoped = true
	auth := &stubAuthQuery{permRows: wildcardSelectGrant(), globalRows: nil}
	s, qc := newService(t, table, auth)

	err := s.Patch(context.Background(), 42, 7, map[string]any{"id": int64(1)}, map[string]any{"amount": int64(5)})
	if !errors.Is(err, errSentinel) {
		t.Fatalf("Patch returned %v, want sentinel", err)
	}
	want := `UPDATE "public"."user_account" SET "amount" = $1, "updated_at" = now(), "updated_by" = $2 WHERE "id" = $3 AND "id" IN (SELECT user_id FROM "partner_user" WHERE partner_id = $4)`
	if qc.sql != want {
		t.Fatalf("sql\n got %s\nwant %s", qc.sql, want)
	}
	if len(qc.args) != 4 || qc.args[3] != int64(42) {
		t.Fatalf("args = %v", qc.args)
	}
}
