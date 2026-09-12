package rest

import (
	"context"
	"fmt"
	"log"
	"maps"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

const (
	qConstantHeader   = "constant_header"
	qConstantValue    = "constant_value"
	qConstantLookup   = "constant_lookup"
	qForeignKeyLookup = "foreign_key_lookup"
	qRestApiHeader    = "rest_api_header"
	qRestApiChild     = "rest_api_child"
	qRestReportHeader = "rest_report_header"
	qRestReportParam  = "rest_report_param"
	qTableAction      = "table_action"
	qTableGrants      = "table_grants"
)

var restQueries = map[string]string{
	qConstantHeader:   "SELECT id, caption FROM constant_header",
	qConstantValue:    "SELECT constant_id, value, caption FROM constant_value",
	qForeignKeyLookup: "SELECT constraint_name, lookup_style, display_column FROM foreign_key_lookup",
	qConstantLookup:   "SELECT table_name, column_name, constant_id FROM constant_lookup",
	qRestApiHeader:    "SELECT id, version, master_table FROM rest_api_header where is_active IS TRUE",
	qRestApiChild:     "SELECT api_id, seq, parent_seq, constraint_name FROM rest_api_child ORDER BY api_id, seq",
	qTableGrants: `
SELECT DISTINCT low_limit
  FROM authorization_role_permission
 WHERE authorization_object_id = 'TABLE'
   AND is_active IS TRUE`,
	qRestReportHeader: "SELECT id, version, query_name, description FROM rest_report_header WHERE is_active IS TRUE",
	qRestReportParam:  "SELECT report_id, seq, param_name, data_type, constant_id FROM rest_report_param ORDER BY report_id, seq",
	qTableAction: `
SELECT table_name, action_name, caption, COALESCE(icon, ''),
       record_specific, COALESCE(method_name, ''),
       display_order, COALESCE(confirm_message, ''),
       action_kind
  FROM table_action
 ORDER BY table_name, display_order, action_name`,
}

type Permission struct {
	ObjectName string
	Action     string
	Low        string
	High       string
}

type ApplicationMenuItem struct {
	MenuId       string
	ItemId       string
	Caption      string
	RestUri      string
	FilterOnList bool
}

type ApplicationMenu struct {
	Id                   string
	Caption              string
	ApplicationMenuItems []ApplicationMenuItem
}

type ReportParam struct {
	Name     string
	DataType string
	// ConstantID points to a constant_header.id when this parameter should
	// render as a dropdown filled from the corresponding constant_value rows
	// (e.g. status, priority). Empty string means no domain — the frontend
	// shows a plain input typed by DataType.
	ConstantID string
}

type RestReport struct {
	Id        string
	Version   string
	QueryName string
	// Long-form text rendered as the report's page header. The short
	// nav-rail label comes from application_menu_item.caption — there's
	// no need to duplicate it here. NOT NULL in the schema; every report
	// must have a description.
	Description string
	Params      []*ReportParam
}

type RestService struct {
	RestApis    map[string]*RestAPI
	RestReports map[string]*RestReport
	// Journal receives the startup audit of TABLE grants versus mounted
	// generic-CRUD tables (auditGrants). nil skips the audit.
	Journal logger.ApplicationLogger
	// GrantCatalog resolves each principal kind's grant SQL; nil uses
	// data.DefaultGrantCatalog.
	GrantCatalog port.GrantCatalog
	db           port.DatabaseRepository
	qs           port.QueryService

	// cacheMu guards reads of the four lazily-populated caches below.
	// Population goes through cacheLoad (singleflight): concurrent
	// first-callers collapse to one DB load instead of every caller
	// running the query and racing on the write lock (v0.4.5 perf,
	// extending the P1-33 DCL fix). cacheMu still protects the bare
	// pointer reads on the steady-state hit path.
	cacheMu       sync.RWMutex
	cacheLoad     singleflight.Group
	cacheConstant map[string]map[string]string
	cacheTable    map[string]map[string]string
	cacheMenu     []*ApplicationMenu
	cacheApis     map[string]any
}

// childNode is one rest_api_child row resolved to its relation, pending linking.
type childNode struct {
	seq, parentSeq int
	pascal         string
	rel            RelationAPI
}

// linkChildRelations attaches each node under its parent_seq's ChildServices, or
// to root when parent_seq is 0 or unresolved (the historic flat behavior).
func linkChildRelations(root map[string]RelationAPI, nodes []*childNode) {
	bySeq := make(map[int]*childNode, len(nodes))
	for _, n := range nodes {
		bySeq[n.seq] = n
	}
	for _, n := range nodes {
		if parent, ok := bySeq[n.parentSeq]; n.parentSeq != 0 && ok {
			parent.rel.ChildServices[n.pascal] = n.rel
		} else {
			root[n.pascal] = n.rel
		}
	}
}

func (s *RestService) Init(ctx context.Context, oltpDatabase port.DatabaseRepository) (map[string]*RestAPI, map[string]*RestReport, error) {
	if oltpDatabase == nil {
		return nil, nil, fmt.Errorf("database repository is required for REST services")
	}
	s.db = oltpDatabase
	if s.GrantCatalog == nil {
		if provider, ok := oltpDatabase.(port.GrantCatalogProvider); ok {
			s.GrantCatalog = provider.Grants()
		}
	}
	// Grant SQL is generated per principal kind, so it is merged in here rather
	// than declared with the rest engine's own.
	queries := make(map[string]string, len(restQueries)+4)
	maps.Copy(queries, restQueries)
	maps.Copy(queries, s.grants().Queries())
	s.qs = oltpDatabase.GetQueryService(ctx, queries)

	res, err := s.qs.Query(ctx, qConstantLookup)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range res.Rows {
		tableName := common.AsString(row[0])
		columnName := common.AsString(row[1])
		constantID := common.AsString(row[2])
		table := s.db.GetTableDefinition(tableName)
		if table == nil {
			return nil, nil, fmt.Errorf("table definition %s not found", tableName)
		}
		for _, col := range table.Columns {
			if col.ColumnName == columnName {
				col.LookupDomain = constantID
				col.InputType = "select"
				break
			}
		}
	}

	s.RestApis = make(map[string]*RestAPI)
	res, err = s.qs.Query(ctx, qRestApiHeader)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range res.Rows {
		tableName := common.AsString(row[2])
		svc := s.db.GetTableService(tableName)
		if svc == nil {
			return nil, nil, fmt.Errorf("table service %q not found for REST API %q", tableName, common.AsString(row[0]))
		}
		restAPI := &RestAPI{
			APIName: common.AsString(row[0]),
			Version: common.AsString(row[1]),
			Relations: RelationAPI{
				DataService:   svc,
				ChildServices: make(map[string]RelationAPI),
				// Database wires the transactional Post path
				// (P1-35). Required at construction time so a
				// freshly-initialized RelationAPI can run Post
				// without further configuration.
				Database: s.db,
			},
		}
		s.RestApis[restAPI.APIName] = restAPI
	}

	res, err = s.qs.Query(ctx, qRestApiChild)
	if err != nil {
		return nil, nil, err
	}
	// Nest each child per rest_api_child.parent_seq (0 = direct child of the
	// master). Two passes so row order is irrelevant; an unresolved parent_seq
	// falls back to the master (the historic flat behavior).
	byAPI := make(map[string][]*childNode)
	for _, row := range res.Rows {
		apiID := common.AsString(row[0])
		if _, ok := s.RestApis[apiID]; !ok {
			continue
		}
		consName := common.AsString(row[3])
		fk := s.db.GetForeignKey(consName)
		if fk == nil {
			return nil, nil, fmt.Errorf("foreign key %s not found in the database", consName)
		}
		ms := s.db.GetTableService(fk.Child.TableName)
		if ms == nil {
			return nil, nil, fmt.Errorf("table service %s not found for REST API %s", fk.Child.TableName, apiID)
		}
		// Key by PascalName to match the frontend JSON field; children inherit
		// Database so the recursive tx Post path resolves services at every level.
		byAPI[apiID] = append(byAPI[apiID], &childNode{
			seq:       int(common.AsInt64(row[1])),
			parentSeq: int(common.AsInt64(row[2])),
			pascal:    fk.PascalName,
			rel: RelationAPI{
				DataService:    ms,
				ParentRelation: fk,
				ChildServices:  make(map[string]RelationAPI),
				Database:       s.db,
			},
		})
	}
	for apiID, nodes := range byAPI {
		linkChildRelations(s.RestApis[apiID].Relations.ChildServices, nodes)
	}
	// Diagnostic failures must not prevent otherwise valid routes from starting.
	if err := s.auditGrants(ctx); err != nil {
		s.Journal.Warning("REST grant audit failed: " + err.Error())
	}

	// Table actions — populate TableDefinition.Actions from the basis
	// table_action rows. Each row becomes one button surfaced in sail's
	// CRUD UIs (next to per-row edit/delete or next to "New Record",
	// depending on record_specific). Reserved action_name values that
	// would collide with generic-CRUD subpaths are rejected up-front
	// so a bad seed fails at boot instead of mis-routing requests.
	if err := s.loadTableActions(ctx); err != nil {
		return nil, nil, err
	}

	s.RestReports = make(map[string]*RestReport)
	res, err = s.qs.Query(ctx, qRestReportHeader)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range res.Rows {
		restReport := &RestReport{
			Id:          common.AsString(row[0]),
			Version:     common.AsString(row[1]),
			QueryName:   common.AsString(row[2]),
			Description: common.AsString(row[3]),
			Params:      make([]*ReportParam, 0),
		}
		s.RestReports[restReport.Id] = restReport
	}
	res, err = s.qs.Query(ctx, qRestReportParam)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range res.Rows {
		restReport, ok := s.RestReports[common.AsString(row[0])]
		if !ok {
			continue
		}
		restReport.Params = append(restReport.Params, &ReportParam{
			Name:       common.AsString(row[2]),
			DataType:   common.AsString(row[3]),
			ConstantID: common.AsString(row[4]),
		})
	}

	return s.RestApis, s.RestReports, nil
}

// auditGrants warns per TABLE grant not reachable through an active
// rest_api_header and per mounted master table no role can reach.
// A '*' grant covers every mounted table.
func (s *RestService) auditGrants(ctx context.Context) error {
	if s.Journal == nil {
		return nil
	}
	res, err := s.qs.Query(ctx, qTableGrants)
	if err != nil {
		return err
	}
	granted := make(map[string]struct{}, len(res.Rows))
	for _, row := range res.Rows {
		granted[common.AsString(row[0])] = struct{}{}
	}
	_, wildcard := granted["*"]

	mounted := make(map[string]struct{}, len(s.RestApis))
	for _, api := range s.RestApis {
		collectMountedTables(api.Relations, mounted)
	}
	for table := range granted {
		if _, ok := mounted[table]; !ok && table != "*" {
			s.Journal.Warning("TABLE grant on " + table + " has no generic CRUD route (no active rest_api_header)")
		}
	}
	if wildcard {
		return nil
	}
	for _, api := range s.RestApis {
		table := api.Relations.DataService.GetTable().TableName
		if _, ok := granted[table]; !ok {
			s.Journal.Warning("rest_api_header " + api.APIName + " exposes " + table + " but no active role permission grants TABLE access to it")
		}
	}
	return nil
}

func collectMountedTables(rel RelationAPI, out map[string]struct{}) {
	out[rel.DataService.GetTable().TableName] = struct{}{}
	for _, child := range rel.ChildServices {
		collectMountedTables(child, out)
	}
}

// grants returns the injected catalog, or the process default.
func (s *RestService) grants() port.GrantCatalog {
	if s.GrantCatalog == nil {
		return data.DefaultGrantCatalog
	}
	return s.GrantCatalog
}

func (s *RestService) GetPermission(ctx context.Context, principal model.Principal) ([]*Permission, error) {
	if s.qs == nil {
		return nil, fmt.Errorf("permission query service is not initialized")
	}
	catalog := s.grants()
	args, err := catalog.Args(principal)
	if err != nil {
		return nil, err
	}
	res, err := s.qs.Query(ctx, catalog.ReadQuery(principal.Kind), args...)
	if err != nil {
		return nil, err
	}
	result := make([]*Permission, len(res.Rows))
	for i, rec := range res.Rows {
		result[i] = &Permission{
			ObjectName: common.AsString(rec[0]),
			Action:     common.AsString(rec[1]),
			Low:        common.AsString(rec[2]),
			High:       common.AsString(rec[3]),
		}
	}
	return result, nil
}

func (s *RestService) GetConstantCache(ctx context.Context) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string)
	res, err := s.qs.Query(ctx, qConstantHeader)
	if err != nil {
		return nil, err
	}
	for _, row := range res.Rows {
		id := common.AsString(row[0])
		result[id] = make(map[string]string)
	}
	res, err = s.qs.Query(ctx, qConstantValue)
	if err != nil {
		return nil, err
	}
	for _, row := range res.Rows {
		id := common.AsString(row[0])
		key := common.AsString(row[1])
		value := common.AsString(row[2])
		result[id][key] = value
	}
	return result, nil
}

func (s *RestService) GetTableCache(ctx context.Context) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string)
	res, err := s.qs.Query(ctx, qForeignKeyLookup)
	if err != nil {
		return nil, err
	}
	for _, row := range res.Rows {
		constraintName := common.AsString(row[0])
		lookupStyle := common.AsString(row[1])
		displayColumn := common.AsString(row[2])
		if lookupStyle == "D" {
			fk := s.db.GetForeignKey(constraintName)
			if fk == nil {
				warning := "foreign_key_lookup names unknown constraint " + constraintName + "; dropdown skipped"
				if s.Journal != nil {
					s.Journal.Warning(warning)
				} else {
					log.Print(warning)
				}
				continue
			}
			table := fk.Parent
			if table.TableName == "" {
				continue
			}
			svc := s.db.GetTableService(table.TableName)
			if svc == nil {
				continue
			}
			result[table.TableName] = make(map[string]string)
			// Dropdown values are the parent's own id — the last key column.
			keyCol := table.Keys[len(table.Keys)-1]
			qColumn := displayColumn
			if displayColumn == keyCol.ColumnName {
				qColumn = ""
			}
			data, err := svc.Get(ctx, 0, 0, nil, qColumn)
			if err != nil {
				return nil, err
			}
			keyPascal := keyCol.PascalName
			valPascal := common.PascalCase(displayColumn)
			for _, rec := range data {
				r := rec.(map[string]any)
				key := common.AsString(r[keyPascal])
				value := common.AsString(r[valPascal])
				result[table.TableName][key] = value
			}
		}
	}
	return result, nil
}

func (s *RestService) GetMenuData(ctx context.Context) ([]*ApplicationMenu, error) {
	params := map[string]any{"is_active": true}
	menuh, err := s.db.GetTableService("application_menu").Get(ctx, 0, 0, params, "display_order")
	if err != nil {
		return nil, err
	}
	menui, err := s.db.GetTableService("application_menu_item").Get(ctx, 0, 0, params, "display_order")
	if err != nil {
		return nil, err
	}

	result := make([]*ApplicationMenu, len(menuh))
	for i, rec := range menuh {
		r := rec.(map[string]any)
		menu := &ApplicationMenu{
			Id:      common.AsString(r["Id"]),
			Caption: common.AsString(r["Caption"]),
		}
		result[i] = menu
	}
	for _, rec := range menui {
		r := rec.(map[string]any)
		menuId := common.AsString(r["MenuId"])
		for _, menu := range result {
			if menu.Id == menuId {
				item := ApplicationMenuItem{
					MenuId:       menuId,
					ItemId:       common.AsString(r["ItemId"]),
					Caption:      common.AsString(r["Caption"]),
					RestUri:      common.AsString(r["RestUri"]),
					FilterOnList: common.AsBool(r["FilterOnList"]),
				}
				menu.ApplicationMenuItems = append(menu.ApplicationMenuItems, item)
			}
		}
	}
	return result, nil
}

// GetClientCache builds the per-user projection of constants, tables,
// menu, and REST API definitions. Individual cache slots are lazily
// populated; concurrent first-callers serialize on cacheMu so a
// burst of requests doesn't double-fill the maps (P1-33). Permissions
// are NOT cached because they're per-user and small.
func (s *RestService) GetClientCache(ctx context.Context, userId int) (map[string]any, error) {
	if err := s.ensureCacheConstant(ctx); err != nil {
		return nil, err
	}
	if err := s.ensureCacheTable(ctx); err != nil {
		return nil, err
	}
	if err := s.ensureCacheMenu(ctx); err != nil {
		return nil, err
	}
	s.ensureCacheApis()

	permissions, err := s.GetPermission(ctx, model.UserPrincipal(userId))
	if err != nil {
		return nil, err
	}
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return map[string]any{
		"ConstantCache":    s.cacheConstant,
		"TableCache":       s.cacheTable,
		"Apis":             s.cacheApis,
		"Reports":          s.RestReports,
		"MainMenu":         s.cacheMenu,
		"Permissions":      permissions,
		"TableDefinitions": s.GetTableDefinitions(),
	}, nil
}

// ensureCacheConstant lazily populates s.cacheConstant. The fast path
// is a single RLock-guarded nil check. On miss, singleflight.Do
// keyed by slot name collapses concurrent first-callers to one DB
// load — the previous DCL pattern let every caller run the query
// before racing on the write lock (v0.4.5 perf).
func (s *RestService) ensureCacheConstant(ctx context.Context) error {
	s.cacheMu.RLock()
	loaded := s.cacheConstant != nil
	s.cacheMu.RUnlock()
	if loaded {
		return nil
	}
	_, err, _ := s.cacheLoad.Do("constant", func() (any, error) {
		s.cacheMu.RLock()
		already := s.cacheConstant != nil
		s.cacheMu.RUnlock()
		if already {
			return nil, nil
		}
		cache, err := s.GetConstantCache(ctx)
		if err != nil {
			return nil, err
		}
		s.cacheMu.Lock()
		if s.cacheConstant == nil {
			s.cacheConstant = cache
		}
		s.cacheMu.Unlock()
		return nil, nil
	})
	return err
}

func (s *RestService) ensureCacheTable(ctx context.Context) error {
	s.cacheMu.RLock()
	loaded := s.cacheTable != nil
	s.cacheMu.RUnlock()
	if loaded {
		return nil
	}
	_, err, _ := s.cacheLoad.Do("table", func() (any, error) {
		s.cacheMu.RLock()
		already := s.cacheTable != nil
		s.cacheMu.RUnlock()
		if already {
			return nil, nil
		}
		cache, err := s.GetTableCache(ctx)
		if err != nil {
			return nil, err
		}
		s.cacheMu.Lock()
		if s.cacheTable == nil {
			s.cacheTable = cache
		}
		s.cacheMu.Unlock()
		return nil, nil
	})
	return err
}

func (s *RestService) ensureCacheMenu(ctx context.Context) error {
	s.cacheMu.RLock()
	loaded := s.cacheMenu != nil
	s.cacheMu.RUnlock()
	if loaded {
		return nil
	}
	_, err, _ := s.cacheLoad.Do("menu", func() (any, error) {
		s.cacheMu.RLock()
		already := s.cacheMenu != nil
		s.cacheMu.RUnlock()
		if already {
			return nil, nil
		}
		cache, err := s.GetMenuData(ctx)
		if err != nil {
			return nil, err
		}
		s.cacheMu.Lock()
		if s.cacheMenu == nil {
			s.cacheMenu = cache
		}
		s.cacheMu.Unlock()
		return nil, nil
	})
	return err
}

func (s *RestService) ensureCacheApis() {
	s.cacheMu.RLock()
	loaded := s.cacheApis != nil
	s.cacheMu.RUnlock()
	if loaded {
		return
	}
	_, _, _ = s.cacheLoad.Do("apis", func() (any, error) {
		s.cacheMu.RLock()
		already := s.cacheApis != nil
		s.cacheMu.RUnlock()
		if already {
			return nil, nil
		}
		apis := make(map[string]any, len(s.RestApis))
		for _, api := range s.RestApis {
			apis[api.APIName] = api.GetDefinition()
		}
		s.cacheMu.Lock()
		if s.cacheApis == nil {
			s.cacheApis = apis
		}
		s.cacheMu.Unlock()
		return nil, nil
	})
}

// InvalidateCache drops every cached slot so the next GetClientCache
// call re-loads from the DB. Use after admin tooling mutates the
// constant / menu / API metadata tables — without this, changes are
// invisible until the process restarts. (P1-34, additive.)
func (s *RestService) InvalidateCache() {
	s.cacheMu.Lock()
	s.cacheConstant = nil
	s.cacheTable = nil
	s.cacheMenu = nil
	s.cacheApis = nil
	s.cacheMu.Unlock()
}

func (s *RestService) TypeScriptTables(ctx context.Context, baseclass string, indent int) []*[]byte {
	return s.db.TypeScriptTables(baseclass, indent)
}

func (s *RestService) GetTableDefinitions() map[string]*model.TableDefinition {
	return s.db.GetTableDefinitions()
}

// loadTableActions reads basis table_action rows and attaches them to
// each matching TableDefinition.Actions slice. Rejects reserved
// action_name values (list / get / post / delete / get-paginated) so a
// bad seed fails at boot instead of mis-routing requests at runtime.
//
// Tables missing from TableDefinitions silently skip — useful when a
// downstream app pre-seeds table_action rows for tables that haven't
// loaded yet (deferred load order is supported).
func (s *RestService) loadTableActions(ctx context.Context) error {
	// The basis table is named `table_action`; the table_action row
	// for the metadata table itself is intentionally absent (we never
	// register custom buttons against the metadata).
	if _, ok := s.db.GetTableDefinitions()["table_action"]; !ok {
		return nil // table_action not loaded — skip silently
	}
	res, err := s.qs.Query(ctx, qTableAction)
	if err != nil {
		return fmt.Errorf("load table_action rows: %w", err)
	}
	for _, row := range res.Rows {
		tableName := common.AsString(row[0])
		actionName := common.AsString(row[1])
		if model.IsReservedActionName(actionName) {
			return fmt.Errorf("table_action.action_name %q collides with a generic-CRUD subpath (%s.%s)",
				actionName, tableName, actionName)
		}
		table := s.db.GetTableDefinition(tableName)
		if table == nil {
			// Unknown target table — skip silently rather than fail boot;
			// downstream apps may seed actions for tables loaded later
			// or that exist only in a sibling schema.
			continue
		}
		action := &model.TableAction{
			TableName:       tableName,
			ActionName:      actionName,
			Caption:         common.AsString(row[2]),
			Icon:            common.AsString(row[3]),
			RecordSpecific:  common.AsBool(row[4]),
			MethodName:      common.AsString(row[5]),
			DisplayOrder:    int(common.AsInt64(row[6])),
			ConfirmMessage:  common.AsString(row[7]),
			Kind:            common.AsString(row[8]),
			AuthorityObject: strings.ToUpper(tableName),
			AuthorityAction: strings.ToUpper(actionName),
		}
		// Method is the resolved URL POST target relative to
		// RestURL.api_prefix on the sail side (which prepends /api/).
		// Convention: <APIVersion>/{table}/{action_name}, mirroring the
		// generic CRUD path <APIVersion>/{apiName}/list / /get / /post /
		// /delete that the downstream's GetApiHandlers loop already
		// mounts. method_name overrides the {table}/{action_name}
		// segment when set — useful for routing two tables' actions to
		// one shared handler at a custom URL.
		if action.MethodName != "" {
			action.Method = common.APIVersion + "/" + action.MethodName
		} else {
			action.Method = common.APIVersion + "/" + tableName + "/" + actionName
		}
		table.Actions = append(table.Actions, action)
	}
	return nil
}
