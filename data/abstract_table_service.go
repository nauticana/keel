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

// CheckPermission returns (allowed, ownScope). `allowed` is true when
// the caller has any permission row matching the (table, action) pair.
// `ownScope` is true when the match is via a wildcard / range pattern
// — i.e. the caller has broad table reach, not an explicit per-table
// grant — and is the signal Get/Insert/Update/Delete use to decide
// whether to apply the UserSpecific row filter. An explicit grant
// (low_limit == exact table name) returns ownScope=false, so admin
// roles like FINANCE_ADMIN that list each table explicitly bypass
// the per-row filter and can read across all owners.
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
	wildcardMatched := false
	for _, rec := range res.Rows {
		lowLimit := common.AsString(rec[0])
		highLimit := common.AsString(rec[1])
		// Explicit per-table grant — full access across rows. Return
		// immediately so a wildcard row in the same result set can't
		// downgrade an admin's explicit grant to own-rows-only.
		if lowLimit == s.Table.TableName {
			return true, false
		}
		// path.Match (not filepath.Match) so the glob semantics are
		// OS-independent — table names use `/` as a logical
		// separator on every platform keel runs on, but
		// filepath.Match flips to `\` on Windows and produces
		// surprising results. (P2-23.)
		if matched, _ := path.Match(lowLimit, s.Table.TableName); matched {
			wildcardMatched = true
		}
		if highLimit != "" && s.Table.TableName >= lowLimit && s.Table.TableName <= highLimit {
			wildcardMatched = true
		}
	}
	if wildcardMatched {
		return true, true
	}
	return false, false
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
