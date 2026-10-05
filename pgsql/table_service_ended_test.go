package pgsql

import (
	"context"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
)

func membershipTable(endedReadOnly bool) *model.TableDefinition {
	partner := &model.TableColumn{ColumnName: "partner_id", PascalName: "PartnerId", IsKey: true}
	user := &model.TableColumn{ColumnName: "user_id", PascalName: "UserId", IsKey: true}
	begda := &model.TableColumn{ColumnName: "begda", PascalName: "Begda", IsKey: true, DataType: model.DT_TIME}
	return &model.TableDefinition{
		TableName:     "partner_user",
		Columns:       []*model.TableColumn{partner, user, begda, {ColumnName: "endda", PascalName: "Endda", DataType: model.DT_TIME}},
		Keys:          []*model.TableColumn{partner, user, begda},
		EndedReadOnly: endedReadOnly,
	}
}

// Generic Update, Patch and Delete must not touch a row whose endda is set.
func TestEndedRowsAreReadOnly(t *testing.T) {
	ctx := context.Background()
	key := map[string]any{"partner_id": int64(1), "user_id": int64(2), "begda": "2026-01-01"}
	for _, guarded := range []bool{true, false} {
		auth := &stubAuthQuery{permRows: wildcardSelectGrant(), globalRows: nil}
		s, qc := newService(t, membershipTable(guarded), auth)
		calls := map[string]func() error{
			"update": func() error {
				return s.Update(ctx, 0, 7, map[string]any{"partner_id": int64(1), "user_id": int64(2), "begda": "2026-01-01", "endda": nil})
			},
			"patch":            func() error { return s.Patch(ctx, 0, 7, key, map[string]any{"endda": "2027-01-01"}) },
			"delete":           func() error { return s.Delete(ctx, 0, 7, key) },
			"delete by filter": func() error { return s.Delete(ctx, 0, 7, map[string]any{"user_id": int64(2)}) },
		}
		for name, call := range calls {
			qc.sql = ""
			_ = call()
			if qc.sql == "" {
				t.Fatalf("%s issued no statement", name)
			}
			if got := strings.HasSuffix(qc.sql, ` AND "endda" IS NULL`); got != guarded {
				t.Errorf("%s (guarded=%v): %s", name, guarded, qc.sql)
			}
		}
	}
}
