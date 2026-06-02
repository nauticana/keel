package data

import (
	"context"
	"path"
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
		highLimit := common.AsString(rec[1])
		rowBypass := common.AsBool(rec[2])
		if lowLimit == s.Table.TableName {
			allowed = true
			if rowBypass {
				bypassScope = true
			}
			continue
		}
		// path.Match (not filepath.Match) so the glob semantics are
		// OS-independent — table names use `/` as a logical
		// separator on every platform keel runs on, but
		// filepath.Match flips to `\` on Windows and produces
		// surprising results. (P2-23.)
		if matched, _ := path.Match(lowLimit, s.Table.TableName); matched {
			allowed = true
			if rowBypass {
				bypassScope = true
			}
		}
		if highLimit != "" && s.Table.TableName >= lowLimit && s.Table.TableName <= highLimit {
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
	if val.Kind() == reflect.Map {
		m := item.(map[string]any)
		if v, ok := m[col.PascalName]; ok {
			return v
		} else if v, ok := m[col.ColumnName]; ok {
			return v
		}
		return nil
	}
	return val.FieldByName(col.PascalName).Interface()
}
