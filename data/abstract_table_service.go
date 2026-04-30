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

func (s *AbstractTableService) CheckPermission(ctx context.Context, userID int, action string) bool {
	if s.AuthQuery == nil || userID < 0 || action == "" {
		return false
	}
	res, err := s.AuthQuery.Query(ctx, QCheckAuthorization, "TABLE", action, userID, s.Table.TableName)
	if err != nil {
		return false
	}
	if len(res.Rows) == 0 {
		return false
	}
	for _, rec := range res.Rows {
		lowLimit := common.AsString(rec[0])
		highLimit := common.AsString(rec[1])
		// path.Match (not filepath.Match) so the glob semantics are
		// OS-independent — table names use `/` as a logical
		// separator on every platform keel runs on, but
		// filepath.Match flips to `\` on Windows and produces
		// surprising results. (P2-23.)
		if matched, _ := path.Match(lowLimit, s.Table.TableName); matched {
			return true
		}
		if highLimit != "" && s.Table.TableName >= lowLimit && s.Table.TableName <= highLimit {
			return true
		}
	}
	return false
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
