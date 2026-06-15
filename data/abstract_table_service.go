package data

import (
	"context"
	"reflect"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type AbstractTableService struct {
	Table       *model.TableDefinition
	AuthQuery   QueryService
	IdGenerator port.BigintGenerator
}

func (s *AbstractTableService) GetTable() *model.TableDefinition {
	return s.Table
}

// IsGlobalRole reports whether userID holds any role in GlobalRoleIDs
// (SUPER / BUSINESS_ADMIN / SECURITY_ADMIN / SECURITY_OPER / APP_ADMIN
// by default). Used by partner-scoped CRUD paths (e.g. pgsql.Get on a
// PartnerUserScoped table) to decide whether the caller can read across
// partners.
//
// Fail-closed: returns false on any query error or missing AuthQuery so
// a misconfigured deployment applies the stricter scope rather than
// silently granting cross-partner read.
func (s *AbstractTableService) IsGlobalRole(ctx context.Context, userID int) bool {
	if s.AuthQuery == nil || userID <= 0 {
		return false
	}
	res, err := s.AuthQuery.Query(ctx, QCheckGlobalRole, userID)
	if err != nil {
		return false
	}
	return len(res.Rows) > 0
}

// CheckPermission returns (allowed, ownScope). ownScope=true tells the SQL layer to auto-inject the UserSpecific / PartnerSpecific row filter. A matching grant with bypass_scope=TRUE returns ownScope=false (admin opt-in for cross-user audit / review).
func (s *AbstractTableService) CheckPermission(ctx context.Context, userID int, action string) (bool, bool) {
	if s.AuthQuery == nil || userID < 0 || action == "" {
		return false, false
	}
	res, err := s.AuthQuery.Query(ctx, QCheckAuthorization, "TABLE", action, userID, s.Table.TableName)
	if err != nil {
		return false, false
	}
	if len(res.Rows) == 0 {
		return false, false
	}
	allowed := false
	bypassScope := false
	for _, rec := range res.Rows {
		lowLimit := common.AsString(rec[0])
		rowBypass := common.AsBool(rec[2])
		// QCheckAuthorization filters low_limit to the exact table name or
		// '*', so those are the only two grant shapes that reach here.
		// Glob/range low_limit values are NOT surfaced by the query and so
		// are deliberately unsupported — see KR-003 / the README permission
		// notes. The explicit check also fails safe if the query is ever
		// widened: a stray non-matching row can never grant access.
		if lowLimit == s.Table.TableName || lowLimit == "*" {
			allowed = true
			if rowBypass {
				bypassScope = true
			}
		}
	}
	if !allowed {
		return false, false
	}
	return true, !bypassScope
}

func (s *AbstractTableService) ExtractValue(item any, col *model.TableColumn) any {
	val := reflect.ValueOf(item)
	var v any
	if val.Kind() == reflect.Map {
		m := item.(map[string]any)
		mv, ok := m[col.PascalName]
		if !ok {
			mv, ok = m[col.ColumnName]
		}
		if !ok {
			return nil
		}
		v = mv
	} else {
		v = val.FieldByName(col.PascalName).Interface()
	}
	// A form sends "" for a cleared field; for a non-text column that maps to
	// SQL NULL — Postgres can't cast '' to bigint/numeric/bool/timestamp.
	if str, ok := v.(string); ok && str == "" &&
		col.DataType != model.DT_STRING && col.DataType != model.DT_TEXT {
		return nil
	}
	return v
}
