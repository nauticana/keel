package data

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

const (
	QGetColumns        = "get_columns"
	QGetPrimaryKeys    = "get_primary_keys"
	QGetForeignKeys    = "get_foreign_keys"
	QGetFkLookupStyles = "get_fk_lookup_styles"
	QGetColumnDisplay  = "get_column_display"
	QGetSequenceUsage  = "get_sequence_usage"
)

type AbstractRepository struct {
	TableServices    map[string]port.TableService
	TableDefinitions map[string]*model.TableDefinition
	ForeignKeys      map[string]*model.ForeignKey
	QuerySvc         port.QueryService
	// GrantCatalog resolves each principal kind's grant SQL; nil uses DefaultGrantCatalog.
	GrantCatalog port.GrantCatalog
	// AuthQuery carries the generated authorization templates. Populated by
	// concrete repository Init (pgsql/repository.go) so CheckActionPermission
	// can reuse it across calls. Equivalent to the AuthQuery each
	// AbstractTableService is given; promoted to the repository layer
	// so middleware that operates outside any specific TableService
	// (custom action handlers, report dispatchers) can run the same
	// permission check.
	AuthQuery        port.QueryService
	IdGenerator      port.BigintGenerator
	ConnectFn        func(ctx context.Context) error
	LoadColumnsFn    func(ctx context.Context) (map[string][]*model.TableColumn, error)
	CreateTableSvcFn func(ctx context.Context, table *model.TableDefinition) port.TableService

	// PartnerTableName is the table whose presence in a child's FK
	// graph marks the child as PartnerSpecific (the partner_id column
	// is auto-injected as a filter by TableService). Defaults to
	// "business_partner". Lifted out of a hardcode in v0.4.1 (P1-39)
	// so projects with a different multi-tenant root can opt in.
	PartnerTableName string

	// UserTableName is the user-account table whose presence as a
	// parent in a child's FK graph (on a column literally named
	// `user_id`) marks the child as UserSpecific — auto-filtering
	// CRUD by the authenticated user's id. Defaults to
	// "user_account". Tables that own a different user FK column
	// (rider_id, driver_id, payer_id, cancelled_by_user_id, ...)
	// are intentionally NOT auto-scoped — those are multi-actor
	// and need custom handlers.
	UserTableName string
}

// Grants returns the injected catalog, or the process default.
func (r *AbstractRepository) Grants() port.GrantCatalog {
	if r.GrantCatalog == nil {
		return DefaultGrantCatalog
	}
	return r.GrantCatalog
}

// partnerTable returns the configured tenant-root table name,
// defaulting to "business_partner" when unset.
func (r *AbstractRepository) partnerTable() string {
	if r.PartnerTableName == "" {
		return "business_partner"
	}
	return r.PartnerTableName
}

// userTable returns the configured user-account table name,
// defaulting to "user_account" when unset.
func (r *AbstractRepository) userTable() string {
	if r.UserTableName == "" {
		return "user_account"
	}
	return r.UserTableName
}

// IsGlobalRole reports whether userID holds any role listed in
// GlobalRoleIDs — the set of framework roles whose mandate is
// cross-partner data management. Drives the bypass on partner-scoped
// row filters such as user_account's PartnerUserScoped flag.
//
// Returns false on any error (query failure, missing AuthQuery, invalid
// userID) — fail-closed so a broken permission lookup applies the
// stricter scope rather than silently granting cross-partner read.
//
// Takes a user id rather than a Principal: it decides row scoping next to the
// same id used as the row filter itself, not who the acting subject is.
func (r *AbstractRepository) IsGlobalRole(ctx context.Context, userID int) bool {
	if userID <= 0 || r.AuthQuery == nil {
		return false
	}
	res, err := r.AuthQuery.Query(ctx, QCheckGlobalRole, userID)
	if err != nil {
		return false
	}
	return len(res.Rows) > 0
}

// CheckActionPermission generalises the table-bound CheckPermission
// helper on AbstractTableService: any (authObject, action) pair scoped
// to the given `scope` string (typically a table_name or "*") is
// checked against the grant table registered for the principal's kind.
//
// Used by TableAction middleware to gate per-table custom actions —
// see keel/handler/WrapTableAction. authObject + action are the
// (uppercased) authorization_object + authorization_object_action
// values registered by the downstream app.
//
// Scope semantics mirror AbstractTableService.CheckPermission: an exact
// `low_limit == scope` grant returns ownScope=false; a '*' grant returns
// ownScope=true. Only exact + '*' are honored (KR-003).
func (r *AbstractRepository) CheckActionPermission(ctx context.Context, principal model.Principal, authObject, action, scope string) (bool, bool) {
	if authObject == "" || action == "" || r.AuthQuery == nil {
		return false, false
	}
	catalog := r.Grants()
	args, err := catalog.Args(principal)
	if err != nil {
		return false, false
	}
	args = append([]any{authObject, action}, append(args, scope)...)
	res, err := r.AuthQuery.Query(ctx, catalog.CheckQuery(principal.Kind), args...)
	if err != nil || len(res.Rows) == 0 {
		return false, false
	}
	wildcardMatched := false
	for _, rec := range res.Rows {
		lowLimit := common.AsString(rec[0])
		// Exact + '*' only, matching CheckPermission and the generated
		// grant query (KR-003). An exact scope grant is owner-scoped
		// (ownScope=false); a '*' grant is broad (ownScope=true).
		if lowLimit == scope {
			return true, false
		}
		if lowLimit == "*" {
			wildcardMatched = true
		}
	}
	if wildcardMatched {
		return true, true
	}
	return false, false
}

func (r *AbstractRepository) Init(ctx context.Context) error {
	if err := r.ConnectFn(ctx); err != nil {
		return err
	}
	r.TableDefinitions = make(map[string]*model.TableDefinition)
	r.TableServices = make(map[string]port.TableService)

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

	r.applyColumnDisplay(ctx)

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

	// Mark the user-account table for partner_user-mediated row scoping.
	// pgsql.TableServicePgsql.Get / Delete consult this flag and inject
	// `id IN (SELECT user_id FROM partner_user WHERE partner_id = $N)`
	// when the caller is not a GlobalRoleIDs holder. Auto-detection here
	// (rather than a schema YAML opt-in) means a single line covers
	// every downstream that follows keel's user_account convention.
	if userTable := r.TableDefinitions[r.userTable()]; userTable != nil {
		userTable.PartnerUserScoped = true
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

func (r *AbstractRepository) GetTableService(tableName string) port.TableService {
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

// applyColumnDisplay overlays per-column UI overrides (read_only, display_width,
// display_rows) from the column_display_attribute table onto the loaded column
// definitions. Non-fatal if the table is absent — downstream schemas that
// predate it simply get no overrides.
func (r *AbstractRepository) applyColumnDisplay(ctx context.Context) {
	res, err := r.QuerySvc.Query(ctx, QGetColumnDisplay)
	if err != nil {
		return // table missing or unreadable: no overrides
	}
	for _, rec := range res.Rows {
		table := strings.ToLower(common.AsString(rec[0]))
		column := strings.ToLower(common.AsString(rec[1]))
		def := r.TableDefinitions[table]
		if def == nil {
			continue
		}
		for _, col := range def.Columns {
			if col.ColumnName != column {
				continue
			}
			col.DisplayMode = strings.ToUpper(strings.TrimSpace(common.AsString(rec[2])))
			col.DisplayWidth = int(common.AsInt32(rec[3]))
			col.DisplayRows = int(common.AsInt32(rec[4]))
			break
		}
	}
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
			// UserSpecific opt-in: parent is the user-account table AND
			// the FK column is literally named `user_id`. The column
			// check stops multi-actor tables (ride.rider_id, ride.
			// cancelled_by_user_id, ride_payment.payer_id, ...) from
			// being auto-scoped — those need custom handlers because
			// the "owner" depends on which actor is calling.
			if parentName == r.userTable() && columnName == "user_id" {
				childTable.UserSpecific = true
			}
		} else {
			columns[constraintName] = append(columns[constraintName], columnName)
		}
	}

	// Fewer-column FKs first: on a shared last column the composite relation wins.
	names := make([]string, 0, len(r.ForeignKeys))
	for name := range r.ForeignKeys {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		li, lj := len(columns[names[i]]), len(columns[names[j]])
		if li != lj {
			return li < lj
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		fk := r.ForeignKeys[name]
		fkCols := columns[name]
		fk.ChildColumns = make([]*model.TableColumn, len(fkCols))
		fk.Columns = fkCols
		cnt := 0
		for i, fkCol := range fkCols {
			for _, col := range fk.Child.Columns {
				if col.ColumnName == fkCol {
					fk.ChildColumns[cnt] = col
					cnt++
					// Only the last FK column carries the lookup binding; leading columns are ancestor scope.
					if i == len(fkCols)-1 {
						col.LookupTable = fk.Parent.TableName
						if fk.LookupStyle == "D" {
							col.InputType = "select"
						}
						col.LookupStyle = fk.LookupStyle
					}
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
