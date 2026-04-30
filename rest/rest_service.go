package rest

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
)

const (
	qReadAuthorization = "read_authorization"
	qConstantHeader    = "constant_header"
	qConstantValue     = "constant_value"
	qConstantLookup    = "constant_lookup"
	qForeignKeyLookup  = "foreign_key_lookup"
	qRestApiHeader     = "rest_api_header"
	qRestApiChild      = "rest_api_child"
	qRestReportHeader  = "rest_report_header"
	qRestReportParam   = "rest_report_param"
)

var restQueries = map[string]string{
	qReadAuthorization: `
SELECT authorization_object_id, action, low_limit, high_limit
  FROM authorization_role_permission
 WHERE role_id in (
       SELECT role_id
         FROM user_permission
        WHERE user_id = ?
          AND begda <= CURRENT_TIMESTAMP
          AND (endda IS NULL OR endda >= CURRENT_TIMESTAMP) )
   AND is_active IS TRUE
`,
	qConstantHeader:   "SELECT id, caption FROM constant_header",
	qConstantValue:    "SELECT constant_id, value, caption FROM constant_value",
	qForeignKeyLookup: "SELECT constraint_name, lookup_style, display_column FROM foreign_key_lookup",
	qConstantLookup:   "SELECT table_name, column_name, constant_id FROM constant_lookup",
	qRestApiHeader:    "SELECT id, version, master_table FROM rest_api_header where is_active IS TRUE",
	qRestApiChild:     "SELECT api_id, constraint_name FROM rest_api_child",
	qRestReportHeader: "SELECT id, version, query_name FROM rest_report_header WHERE is_active IS TRUE",
	qRestReportParam:  "SELECT report_id, seq, param_name, data_type FROM rest_report_param ORDER BY report_id, seq",
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
}

type RestReport struct {
	Id        string
	Version   string
	QueryName string
	Params    []*ReportParam
}

type RestService struct {
	RestApis    map[string]*RestAPI
	RestReports map[string]*RestReport
	db          data.DatabaseRepository
	qs          data.QueryService

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

func (s *RestService) Init(ctx context.Context, oltpDatabase data.DatabaseRepository) (map[string]*RestAPI, map[string]*RestReport, error) {
	if oltpDatabase == nil {
		return nil, nil, fmt.Errorf("database repository is required for REST services")
	}
	s.db = oltpDatabase
	s.qs = oltpDatabase.GetQueryService(ctx, restQueries)

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
	for _, row := range res.Rows {
		restAPI, ok := s.RestApis[common.AsString(row[0])]
		if !ok {
			continue
		}
		consName := common.AsString(row[1])
		fk := s.db.GetForeignKey(consName)
		if fk == nil {
			return nil, nil, fmt.Errorf("foreign key %s not found in the database", consName)
		}
		ms := s.db.GetTableService(fk.Child.TableName)
		if ms == nil {
			return nil, nil, fmt.Errorf("table service %s not found for REST API %s", fk.Child.TableName, restAPI.APIName)
		}
		// Key by PascalName so it matches the JSON field key sent by the frontend
		// (e.g. "UserPermissions" rather than "user_permissions").
		// Children inherit Database from the parent so the recursive
		// transactional Post path can resolve tx-bound services for
		// every level.
		restAPI.Relations.ChildServices[fk.PascalName] = RelationAPI{
			DataService:    ms,
			ParentRelation: fk,
			ChildServices:  make(map[string]RelationAPI),
			Database:       s.db,
		}
	}

	s.RestReports = make(map[string]*RestReport)
	res, err = s.qs.Query(ctx, qRestReportHeader)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range res.Rows {
		restReport := &RestReport{
			Id:        common.AsString(row[0]),
			Version:   common.AsString(row[1]),
			QueryName: common.AsString(row[2]),
			Params:    make([]*ReportParam, 0),
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
			Name:     common.AsString(row[2]),
			DataType: common.AsString(row[3]),
		})
	}

	return s.RestApis, s.RestReports, nil
}

func (s *RestService) GetPermission(ctx context.Context, userId int) ([]*Permission, error) {
	if s.qs == nil || userId < 0 {
		return nil, fmt.Errorf("permission query service is not initialized")
	}
	res, err := s.qs.Query(ctx, qReadAuthorization, userId)
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
			table := s.db.GetForeignKey(constraintName).Parent
			if table.TableName == "" {
				continue
			}
			svc := s.db.GetTableService(table.TableName)
			if svc == nil {
				continue
			}
			result[table.TableName] = make(map[string]string)
			keyName := table.Keys[0].ColumnName
			qColumn := displayColumn
			if displayColumn == keyName {
				qColumn = ""
			}
			data, err := svc.Get(ctx, 0, 0, nil, qColumn)
			if err != nil {
				return nil, err
			}
			keyPascal := table.Keys[0].PascalName
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

	permissions, err := s.GetPermission(ctx, userId)
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
