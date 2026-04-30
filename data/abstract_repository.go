package data

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

const (
	QGetColumns         = "get_columns"
	QGetPrimaryKeys     = "get_primary_keys"
	QGetForeignKeys     = "get_foreign_keys"
	QGetFkLookupStyles  = "get_fk_lookup_styles"
	QGetSequenceUsage   = "get_sequence_usage"
	QCheckAuthorization = "check_permission"
)

var AuthorizationQueries = map[string]string{
	QCheckAuthorization: `
SELECT a.low_limit, a.high_limit
  FROM user_permission p, authorization_role_permission a
 WHERE p.role_id = a.role_id
   AND p.begda <= CURRENT_TIMESTAMP
   AND (p.endda IS NULL OR p.endda >= CURRENT_TIMESTAMP)
   AND a.is_active IS TRUE
   AND a.authorization_object_id = ?
   AND a.action = ?
   AND p.user_id = ?
   AND (a.low_limit = ? OR a.low_limit = '*')
`,
}

type AbstractRepository struct {
	TableServices    map[string]TableService
	TableDefinitions map[string]*model.TableDefinition
	ForeignKeys      map[string]*model.ForeignKey
	QuerySvc         QueryService
	IdGenerator      port.BigintGenerator
	ConnectFn        func(ctx context.Context) error
	LoadColumnsFn    func(ctx context.Context) (map[string][]*model.TableColumn, error)
	CreateTableSvcFn func(ctx context.Context, table *model.TableDefinition) TableService

	// PartnerTableName is the table whose presence in a child's FK
	// graph marks the child as PartnerSpecific (the partner_id column
	// is auto-injected as a filter by TableService). Defaults to
	// "business_partner". Lifted out of a hardcode in v0.4.1 (P1-39)
	// so projects with a different multi-tenant root can opt in.
	PartnerTableName string
}

// partnerTable returns the configured tenant-root table name,
// defaulting to "business_partner" when unset.
func (r *AbstractRepository) partnerTable() string {
	if r.PartnerTableName == "" {
		return "business_partner"
	}
	return r.PartnerTableName
}

func (r *AbstractRepository) Init(ctx context.Context) error {
	if err := r.ConnectFn(ctx); err != nil {
		return err
	}
	r.TableDefinitions = make(map[string]*model.TableDefinition)
	r.TableServices = make(map[string]TableService)

	columns, err := r.LoadColumnsFn(ctx)
	if err != nil {
		return err
	}
	for tableName, cols := range columns {
		table := &model.TableDefinition{
			TableName:  tableName,
			PascalName: common.PascalCase(tableName),
			Caption:    common.TitleCase(tableName),
			Columns:    cols,
			Children:   []*model.ForeignKey{},
		}
		r.TableDefinitions[tableName] = table
	}

	primaryKeys, err := r.LoadPrimaryKeys(ctx)
	if err != nil {
		return err
	}
	for tableName, keys := range primaryKeys {
		table := r.TableDefinitions[tableName]
		table.Keys = make([]*model.TableColumn, len(keys))
		for i, coln := range keys {
			for _, col := range table.Columns {
				if col.ColumnName == coln {
					col.IsKey = true
					table.Keys[i] = col
					break
				}
			}
		}
	}

	fkResult, err := r.GetForeignKeys(ctx)
	if err != nil {
		return err
	}
	lookupStyles, err := r.loadFkLookupStyles(ctx)
	if err != nil {
		return err
	}
	if err := r.LoadForeignKeys(ctx, fkResult, lookupStyles); err != nil {
		// P1-38: this error was previously discarded, leaving Init
		// to silently continue with a partial FK graph. Surface it
		// so misconfigured schemas fail fast at boot.
		return fmt.Errorf("load foreign keys: %w", err)
	}

	for tableName, table := range r.TableDefinitions {
		if len(table.Keys) == 0 || len(table.Columns) == 0 {
			delete(r.TableDefinitions, tableName)
			continue
		}
		r.TableServices[tableName] = r.CreateTableSvcFn(ctx, table)
		if err := r.TableServices[tableName].Init(); err != nil {
			return err
		}
	}
	return nil
}

func (r *AbstractRepository) GetTableDefinitions() map[string]*model.TableDefinition {
	return r.TableDefinitions
}

func (r *AbstractRepository) GetTableDefinition(tableName string) *model.TableDefinition {
	return r.TableDefinitions[tableName]
}

func (r *AbstractRepository) GetTableService(tableName string) TableService {
	return r.TableServices[tableName]
}

func (r *AbstractRepository) GetForeignKey(consName string) *model.ForeignKey {
	return r.ForeignKeys[consName]
}

func (r *AbstractRepository) LoadPrimaryKeys(ctx context.Context) (map[string][]string, error) {
	result := make(map[string][]string)
	res, err := r.QuerySvc.Query(ctx, QGetPrimaryKeys, *common.DBschema)
	if err != nil {
		return nil, err
	}
	for _, rec := range res.Rows {
		tableName := strings.ToLower(common.AsString(rec[0]))
		position := common.AsInt32(rec[1])
		columnName := strings.ToLower(common.AsString(rec[2]))
		if position == 1 {
			result[tableName] = []string{columnName}
		} else {
			result[tableName] = append(result[tableName], columnName)
		}
	}
	return result, nil
}

// loadFkLookupStyles fetches constraint_name -> lookup_style from foreign_key_lookup.
// "D" = dropdown (select), "S" = search popup, "H" = hidden.
func (r *AbstractRepository) loadFkLookupStyles(ctx context.Context) (map[string]string, error) {
	styles := make(map[string]string)
	res, err := r.QuerySvc.Query(ctx, QGetFkLookupStyles)
	if err != nil {
		return styles, nil // non-fatal: if table missing, treat as no styles configured
	}
	for _, rec := range res.Rows {
		styles[common.AsString(rec[0])] = common.AsString(rec[1])
	}
	return styles, nil
}

func (r *AbstractRepository) LoadForeignKeys(ctx context.Context, res *model.QueryResult, lookupStyles map[string]string) error {
	r.ForeignKeys = make(map[string]*model.ForeignKey)
	columns := make(map[string][]string)
	var fk *model.ForeignKey
	for _, rec := range res.Rows {
		childName := strings.ToLower(common.AsString(rec[1]))
		position := common.AsInt32(rec[2])
		columnName := strings.ToLower(common.AsString(rec[3]))
		childTable := r.TableDefinitions[childName]
		if childTable == nil {
			return fmt.Errorf("table %s not defined", childName)
		}
		constraintName := common.AsString(rec[0])
		if position == 1 {
			parentName := common.AsString(rec[4])
			parentTable := r.TableDefinitions[parentName]
			if parentTable == nil {
				return fmt.Errorf("table %s not defined", parentName)
			}
			columns[constraintName] = []string{columnName}
			fk = &model.ForeignKey{
				Parent:         parentTable,
				Child:          childTable,
				ParentTable:    parentTable.TableName,
				ChildTable:     childTable.TableName,
				PascalName:     common.PascalCase(constraintName),
				ConstraintName: constraintName,
				LookupStyle:    lookupStyles[constraintName],
			}
			r.ForeignKeys[constraintName] = fk
			parentTable.Children = append(parentTable.Children, fk)
			childTable.Parents = append(childTable.Parents, fk)
			if parentName == r.partnerTable() {
				childTable.PartnerSpecific = true
			}
		} else {
			columns[constraintName] = append(columns[constraintName], columnName)
		}
	}

	for _, fk := range r.ForeignKeys {
		fk.ChildColumns = make([]*model.TableColumn, len(columns[fk.ConstraintName]))
		fk.Columns = columns[fk.ConstraintName]
		cnt := 0
		for _, fkCol := range columns[fk.ConstraintName] {
			for _, col := range fk.Child.Columns {
				if col.ColumnName == fkCol {
					fk.ChildColumns[cnt] = col
					cnt++
					col.LookupTable = fk.Parent.TableName
					if fk.LookupStyle == "D" {
						col.InputType = "select"
					}
					col.LookupStyle = fk.LookupStyle
					break
				}
			}
		}
	}
	return nil
}

func (r *AbstractRepository) GetForeignKeys(ctx context.Context) (*model.QueryResult, error) {
	result, err := r.QuerySvc.Query(ctx, QGetForeignKeys, *common.DBschema)
	if err != nil {
		return nil, fmt.Errorf("failed to load foreign keys: %w", err)
	}
	return result, nil
}

func (r *AbstractRepository) TypeScriptTables(baseclass string, indent int) []*[]byte {
	space := "                "
	indsp := space[0:indent]
	tables := make([]*[]byte, len(r.TableDefinitions))
	i := 0
	for _, table := range r.TableDefinitions {
		b := []byte(table.TypeScriptWithChildren(baseclass, indsp))
		tables[i] = &b
		i++
	}
	return tables
}
