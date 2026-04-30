package rest

import (
	"context"
	"fmt"
	"reflect"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
)

type RelationAPI struct {
	DataService    data.TableService
	ParentRelation *model.ForeignKey
	ChildServices  map[string]RelationAPI

	// Database, when set, makes Post run its parent + children write
	// batch inside a single DB transaction (P1-35). Wired by
	// RestService.Init from the underlying repository. When nil,
	// Post returns an error rather than committing partially —
	// previous releases ran each Insert / Update / Delete as its
	// own auto-committed write, which left the DB in a half-mutated
	// state on mid-batch failure. v0.4.2 closes that gap; consumers
	// constructing RelationAPI by hand must wire Database before
	// calling Post.
	Database data.DatabaseRepository
}

func (s *RelationAPI) Init() error {
	return s.DataService.Init()
}

func (s *RelationAPI) GetTable() *model.TableDefinition {
	return s.DataService.GetTable()
}

func (s *RelationAPI) Get(ctx context.Context, partnerID int64, userID int, where map[string]any, order string) ([]any, error) {
	records, err := s.DataService.Get(ctx, partnerID, userID, where, order)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		m := record.(map[string]any)
		keyVals := make(map[string]any)
		for _, key := range s.DataService.GetTable().Keys {
			keyVals[key.ColumnName] = m[key.PascalName]
		}
		children, err := s.FetchChildren(ctx, partnerID, userID, keyVals)
		if err != nil {
			return nil, err
		}
		for k, v := range children {
			m[k] = v
		}
	}
	return records, nil
}

func (s *RelationAPI) FetchChildren(ctx context.Context, partnerID int64, userID int, parentKeyValues map[string]any) (map[string]any, error) {
	if s.ChildServices == nil {
		return nil, nil
	}
	results := make(map[string]any)
	for _, childRel := range s.ChildServices {
		fkVals := make(map[string]any)
		for i, keyCol := range s.DataService.GetTable().Keys {
			keyVal := parentKeyValues[keyCol.ColumnName]
			fkVals[childRel.ParentRelation.ChildColumns[i].ColumnName] = keyVal
		}
		childItems, err := childRel.Get(ctx, partnerID, userID, fkVals, "")
		if err != nil {
			return nil, err
		}
		results[childRel.ParentRelation.PascalName] = childItems
	}
	return results, nil
}

func (s *RelationAPI) List(ctx context.Context, partnerID int64, userID int, where map[string]any, order string) ([]any, error) {
	return s.DataService.Get(ctx, partnerID, userID, where, order)
}

func (s *RelationAPI) Insert(ctx context.Context, partnerID int64, userID int, data any) ([]int64, error) {
	return s.DataService.Insert(ctx, partnerID, userID, data)
}

func (s *RelationAPI) Update(ctx context.Context, userID int, data any) error {
	return s.DataService.Update(ctx, userID, data)
}

func (s *RelationAPI) Delete(ctx context.Context, partnerID int64, userID int, where map[string]any) error {
	return s.DataService.Delete(ctx, partnerID, userID, where)
}

func (s *RelationAPI) getChildItems(item any, fieldName string) []any {
	if m, ok := item.(map[string]any); ok {
		val, exists := m[fieldName]
		if !exists {
			return nil
		}
		if arr, ok := val.([]any); ok {
			return arr
		}
		return nil
	}
	var result []any
	val := reflect.Indirect(reflect.ValueOf(item))
	field := val.FieldByName(fieldName)
	if field.IsValid() && field.Kind() == reflect.Slice {
		for i := 0; i < field.Len(); i++ {
			child := field.Index(i)
			if child.Kind() == reflect.Struct {
				result = append(result, child.Addr().Interface())
			} else {
				result = append(result, child.Interface())
			}
		}
	}
	return result
}

func (s *RelationAPI) propogateKeys(parent any) {
	parentTable := s.DataService.GetTable()
	if parentTable == nil {
		return
	}
	if parentMap, ok := parent.(map[string]any); ok {
		for fieldName, childRel := range s.ChildServices {
			var fk *model.ForeignKey
			for _, f := range parentTable.Children {
				if f.PascalName == fieldName {
					fk = f
					break
				}
			}
			if fk == nil || len(fk.ChildColumns) != len(parentTable.Keys) {
				continue
			}
			childItems := s.getChildItems(parent, fieldName)
			for _, child := range childItems {
				if childMap, ok := child.(map[string]any); ok {
					for idx, id := range parentTable.Keys {
						fkCol := fk.ChildColumns[idx]
						childMap[fkCol.PascalName] = parentMap[id.PascalName]
					}
					childRel.propogateKeys(child)
				}
			}
		}
		return
	}
	parentVal := reflect.Indirect(reflect.ValueOf(parent))
	for fieldName, childRel := range s.ChildServices {
		var fk *model.ForeignKey
		for _, f := range parentTable.Children {
			if f.PascalName == fieldName {
				fk = f
				break
			}
		}
		if fk != nil && len(fk.ChildColumns) == len(parentTable.Keys) {
			childField := parentVal.FieldByName(fieldName)
			if childField.IsValid() && childField.Kind() == reflect.Slice {
				for i := 0; i < childField.Len(); i++ {
					child := childField.Index(i)
					var childElem reflect.Value
					if child.Kind() == reflect.Ptr {
						childElem = child.Elem()
					} else {
						childElem = child
					}
					for idx, id := range parentTable.Keys {
						idVal := parentVal.FieldByName(id.PascalName)
						fkCol := fk.ChildColumns[idx]
						target := childElem
						if target.Kind() == reflect.Ptr {
							target = target.Elem()
						}
						fkField := target.FieldByName(fkCol.PascalName)
						if fkField.IsValid() && fkField.CanSet() {
							fkField.Set(idVal)
						}
					}
					childRel.propogateKeys(child.Interface())
				}
			}
		}
	}
}

func (s *RelationAPI) getOpCode(item any) (string, bool) {
	if m, ok := item.(map[string]any); ok {
		if v, exists := m["op_code"]; exists {
			if code, ok := v.(string); ok {
				return code, true
			}
		}
		return "", false
	}
	val := reflect.Indirect(reflect.ValueOf(item))
	opField := val.FieldByName("OPCode")
	if !opField.IsValid() {
		return "", false
	}
	return opField.String(), true
}

func (s *RelationAPI) getKeyFilter(item any, keys []*model.TableColumn) map[string]any {
	where := make(map[string]any)
	if m, ok := item.(map[string]any); ok {
		for _, id := range keys {
			if v, exists := m[id.PascalName]; exists {
				where[id.ColumnName] = v
			} else if v, exists := m[id.ColumnName]; exists {
				where[id.ColumnName] = v
			}
		}
		return where
	}
	val := reflect.Indirect(reflect.ValueOf(item))
	for _, id := range keys {
		where[id.ColumnName] = val.FieldByName(id.PascalName).Interface()
	}
	return where
}

func (s *RelationAPI) setGeneratedID(item any, pkCol *model.TableColumn, id int64) {
	if m, ok := item.(map[string]any); ok {
		m[pkCol.PascalName] = id
		return
	}
	val := reflect.Indirect(reflect.ValueOf(item))
	field := val.FieldByName(pkCol.PascalName)
	if field.IsValid() && field.CanSet() {
		switch field.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			field.SetInt(id)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			field.SetUint(uint64(id))
		case reflect.Float32, reflect.Float64:
			field.SetFloat(float64(id))
		case reflect.String:
			field.SetString(fmt.Sprintf("%d", id))
		}
	}
}

// Post runs the parent + children write batch inside a single DB
// transaction (P1-35, shipped in v0.4.2). The transaction wraps every
// Insert / Update / Delete that fires for the parent AND every
// recursive child relation, so a mid-batch failure rolls the whole
// thing back. Concretely:
//
//   - We open a tx via Database.RunInTx.
//   - The TxView yielded to the callback returns tx-bound copies of
//     every TableService — so calling Insert/Update/Delete on those
//     copies routes the SQL through the running tx, not the pool.
//   - Children recurse with the same view, so deeply-nested
//     parent/child trees end up in one atomic write.
//   - Database.RunInTx commits on a clean return and rolls back on
//     any error (or panic).
//
// Database is a hard requirement: a non-tx fallback would silently
// reintroduce the partial-write hazard P1-35 was filed to fix.
// RestService.Init wires Database for every RelationAPI it builds;
// consumers constructing RelationAPI by hand must do the same.
func (s *RelationAPI) Post(ctx context.Context, partnerID int64, userID int, items ...any) error {
	if len(items) == 0 {
		return nil
	}
	if s.Database == nil {
		return fmt.Errorf("relation: Database is not configured; transactional Post requires it (RestService.Init wires it automatically)")
	}
	if s.DataService.GetTable() == nil {
		return fmt.Errorf("parent table not defined")
	}
	return s.Database.RunInTx(ctx, func(view data.TxView) error {
		return s.postInTx(ctx, view, partnerID, userID, items...)
	})
}

// postInTx is the body of Post — same op-code dispatch as before, but
// every TableService call goes through view.Table(...) so it lands in
// the surrounding transaction. Recursion into children also uses
// view, ensuring the entire relation tree shares one tx.
func (s *RelationAPI) postInTx(ctx context.Context, view data.TxView, partnerID int64, userID int, items ...any) error {
	parentTable := s.DataService.GetTable()
	parentSvc := view.Table(parentTable.TableName)
	if parentSvc == nil {
		return fmt.Errorf("relation: tx view has no service for table %q", parentTable.TableName)
	}
	for _, item := range items {
		opCode, ok := s.getOpCode(item)
		if !ok {
			continue
		}
		switch opCode {
		case "D":
			// Children first so FK constraints don't refuse the
			// parent delete. The recursion uses the same view.
			if err := s.postChildrenInTx(ctx, view, partnerID, userID, item); err != nil {
				return err
			}
			where := s.getKeyFilter(item, parentTable.Keys)
			if err := parentSvc.Delete(ctx, partnerID, userID, where); err != nil {
				return err
			}
		case "I":
			ids, err := parentSvc.Insert(ctx, partnerID, userID, item)
			if err != nil {
				return err
			}
			if len(ids) > 0 && len(parentTable.Keys) == 1 {
				s.setGeneratedID(item, parentTable.Keys[0], ids[0])
			}
			s.propogateKeys(item)
			if err := s.postChildrenInTx(ctx, view, partnerID, userID, item); err != nil {
				return err
			}
		case "U":
			if err := parentSvc.Update(ctx, userID, item); err != nil {
				return err
			}
			s.propogateKeys(item)
			if err := s.postChildrenInTx(ctx, view, partnerID, userID, item); err != nil {
				return err
			}
		case "R":
			// Parent unchanged; children may carry op_codes. Walk
			// keys to client-side parent refs first, then recurse.
			s.propogateKeys(item)
			if err := s.postChildrenInTx(ctx, view, partnerID, userID, item); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown operation code %s", opCode)
		}
	}
	return nil
}

// postChildrenInTx walks the ChildServices map and recurses into
// each child relation that has matching items in the parent payload.
// The same view threads through so every level shares the tx.
func (s *RelationAPI) postChildrenInTx(ctx context.Context, view data.TxView, partnerID int64, userID int, item any) error {
	for fieldName, childRel := range s.ChildServices {
		childItems := s.getChildItems(item, fieldName)
		if len(childItems) == 0 {
			continue
		}
		if err := childRel.postInTx(ctx, view, partnerID, userID, childItems...); err != nil {
			return err
		}
	}
	return nil
}

func (s *RelationAPI) GetDefinition(apiName string, version string) map[string]any {
	result := make(map[string]any)
	result["RestAPI"] = apiName
	result["Version"] = version
	result["Table"] = s.GetTable()
	result["PathType"] = "L"
	if s.ParentRelation == nil {
		result["Caption"] = common.TitleCase(apiName)
		result["PascalName"] = common.PascalCase(apiName)
	} else {
		result["Caption"] = common.TitleCase(s.ParentRelation.ConstraintName)
		result["PascalName"] = s.ParentRelation.PascalName
		myFkColumns := make([]*model.TableColumn, len(s.ParentRelation.ChildColumns))
		for i, coln := range s.ParentRelation.ChildColumns {
			for _, col := range s.GetTable().Columns {
				if col.ColumnName == coln.ColumnName {
					myFkColumns[i] = col
					break
				}
			}
		}
		result["ParentKeys"] = s.ParentRelation.Parent.Keys
		result["ChildKeys"] = myFkColumns
	}
	if s.ChildServices != nil {
		children := make(map[string]map[string]any, len(s.ChildServices))
		for relName, childRel := range s.ChildServices {
			children[relName] = childRel.GetDefinition(apiName, version)
		}
		result["Children"] = children
	}
	return result
}
