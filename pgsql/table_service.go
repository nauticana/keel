package pgsql

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
)

// pgxQuerier is the minimal pgx surface that TableServicePgsql calls
// against. Both *pgxpool.Pool and pgx.Tx satisfy it — having Client be
// an interface (rather than a concrete pool) is what lets WithTx fork
// a tx-bound copy of the service so RelationAPI.Post can run all of
// its writes inside one transaction (P1-35).
type pgxQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type TableServicePgsql struct {
	data.AbstractTableService
	// Client is a pgxQuerier — usually a *pgxpool.Pool, but inside a
	// RunInTx callback Client is a pgx.Tx so the same struct can drive
	// either pooled or transactional writes. Keep this as an
	// interface, not a concrete type — the interface widening was
	// the whole point of the v0.4.2 P1-35 refactor.
	Client        pgxQuerier
	Schema        string
	sqlSelectAll  string
	sqlSelectByID string
	sqlInsertItem string
	sqlUpdateByID string
	sqlDeleteByID string
}

// WithTx returns a shallow copy of the receiver with Client replaced
// by tx. All cached SQL strings, schema metadata, and abstract-base
// state are shared — only the connection underneath is different.
// The returned value is only safe to use for the lifetime of tx.
func (s *TableServicePgsql) WithTx(tx pgx.Tx) *TableServicePgsql {
	cp := *s
	cp.Client = tx
	return &cp
}

func (s *TableServicePgsql) Placeholder(idx int) string {
	return fmt.Sprintf("$%d", idx)
}

// quoteIdent wraps a SQL identifier in double-quotes and escapes any
// embedded `"` so reserved-word column / table names (`user`, `order`,
// `desc`, etc.) round-trip cleanly. PostgreSQL preserves case for
// quoted identifiers — keel schema YAMLs use lowercase, so the
// quoting is purely defensive against keyword collisions and not a
// case-sensitivity change. (P1-44.)
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// quotedTable returns the schema-qualified, double-quoted form of
// the bound table — used in every SQL string built by this service.
func (s *TableServicePgsql) quotedTable() string {
	return quoteIdent(s.Schema) + "." + quoteIdent(s.Table.TableName)
}

// resolveColumnName accepts either the snake_case ColumnName or the
// PascalName form a JSON client would use, and returns the canonical
// column name when it appears in the table's column list. Returns
// "", false for keys not in the table — Get/Delete treat that as a
// SQL-injection attempt and refuse the request.
//
// Without this guard, the WHERE-builder in Get/Delete would inline
// any caller-supplied map key directly into the SQL string. A
// downstream HTTP handler that mapped query-string parameters into
// the where map without filtering would become an arbitrary-SQL
// vector. Centralizing the check at the data layer means every
// caller is protected, even the careless ones.
func (s *TableServicePgsql) resolveColumnName(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	for _, col := range s.Table.Columns {
		if col.ColumnName == key || col.PascalName == key {
			return col.ColumnName, true
		}
	}
	return "", false
}

func (s *TableServicePgsql) Init() error {
	if len(s.Table.Keys) < 1 || len(s.Table.Columns) < 1 {
		return fmt.Errorf("columns or ID fields not defined for table %s.%s", s.Schema, s.Table.TableName)
	}
	var cols []string
	for _, col := range s.Table.Columns {
		cols = append(cols, quoteIdent(col.ColumnName))
	}
	s.sqlSelectAll = fmt.Sprintf("SELECT %s FROM %s", strings.Join(cols, ", "), s.quotedTable())
	idPlaceholders := make([]string, len(s.Table.Keys))
	for i, id := range s.Table.Keys {
		idPlaceholders[i] = fmt.Sprintf("%s = %s", quoteIdent(id.ColumnName), s.Placeholder(i+1))
	}
	whr := " WHERE " + strings.Join(idPlaceholders, " AND ")
	s.sqlSelectByID = s.sqlSelectAll + whr
	s.sqlDeleteByID = "DELETE FROM " + s.quotedTable() + whr

	var updateSet []string
	plcCnt := 1
	for _, col := range s.Table.Columns {
		isId := false
		for _, id := range s.Table.Keys {
			if col.ColumnName == id.ColumnName {
				isId = true
				break
			}
		}
		if isId {
			continue
		}
		updateSet = append(updateSet, fmt.Sprintf("%s = %s", quoteIdent(col.ColumnName), s.Placeholder(plcCnt)))
		plcCnt++
	}
	if len(updateSet) == 0 {
		s.sqlUpdateByID = ""
	} else {
		updateWherePlc := make([]string, len(s.Table.Keys))
		for i := range s.Table.Keys {
			updateWherePlc[i] = fmt.Sprintf("%s = %s", quoteIdent(s.Table.Keys[i].ColumnName), s.Placeholder(plcCnt))
			plcCnt++
		}
		s.sqlUpdateByID = "UPDATE " + s.quotedTable() + " SET " + strings.Join(updateSet, ", ") + " WHERE " + strings.Join(updateWherePlc, " AND ")
	}
	var insertCols []string
	var insertPlchldr []string
	plcCnt = 1
	hasSequence := false
	seqColumn := ""
	for _, col := range s.Table.Columns {
		if col.HasDefault && col.DataType == model.DT_TIME {
			continue
		}
		if col.SequenceName != "" {
			hasSequence = true
			seqColumn = col.ColumnName
			insertCols = append(insertCols, quoteIdent(col.ColumnName))
			insertPlchldr = append(insertPlchldr, fmt.Sprintf("nextval(%s)", quoteSQLString(col.SequenceName)))
		} else {
			insertCols = append(insertCols, quoteIdent(col.ColumnName))
			insertPlchldr = append(insertPlchldr, s.Placeholder(plcCnt))
			plcCnt++
		}
	}
	s.sqlInsertItem = "INSERT INTO " + s.quotedTable() + " (" + strings.Join(insertCols, ", ") + ") VALUES (" + strings.Join(insertPlchldr, ", ") + ")"
	if hasSequence {
		s.sqlInsertItem += " RETURNING " + quoteIdent(seqColumn)
	}
	return nil
}

// quoteSQLString wraps a string for embedding as a SQL literal in
// places where a placeholder isn't accepted (e.g. `nextval('...')`).
// Doubles single-quotes per RFC and rejects backslashes (which
// PostgreSQL treats specially when standard_conforming_strings is
// off). Sequence names produced by the schema YAML pipeline are
// already restricted to ASCII identifiers, so this is a defensive
// belt-and-suspenders check.
func quoteSQLString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (s *TableServicePgsql) Get(ctx context.Context, partnerID int64, userID int, where map[string]any, orderby string) ([]any, error) {
	if userID > 0 && !s.CheckPermission(ctx, userID, "SELECT") {
		return nil, fmt.Errorf("permission denied: SELECT on table %s", s.Table.TableName)
	}
	var sqlText string
	var vals []any

	if s.Table.PartnerSpecific {
		if where == nil {
			where = make(map[string]any)
		}
		// Only fall back to the session's partner when the caller did not
		// scope the query themselves. RelationAPI.FetchChildren propagates
		// the parent's primary key (which includes partner_id for child
		// tables) into `where` before calling Get; overwriting it would
		// silently coerce every child read back to the session's partner
		// — making a SUPER user viewing partner B's details see partner
		// A's rows instead. The top-level /list path doesn't set this
		// key, so the session-scoped partition guard still applies there.
		if _, set := where["partner_id"]; !set {
			where["partner_id"] = partnerID
		}
	}
	if len(where) == len(s.Table.Keys) && len(where) > 0 {
		match := true
		sortedVals := make([]any, len(s.Table.Keys))
		for i, col := range s.Table.Keys {
			if val, ok := where[col.ColumnName]; ok {
				sortedVals[i] = val
			} else {
				match = false
				break
			}
		}
		if match {
			sqlText = s.sqlSelectByID
			vals = sortedVals
		}
	}
	if sqlText == "" {
		sqlText = s.sqlSelectAll
		if len(where) > 0 {
			var conditions []string
			plcCnt := 1
			for k, v := range where {
				colName, ok := s.resolveColumnName(k)
				if !ok {
					return nil, fmt.Errorf("invalid filter column: %s", k)
				}
				conditions = append(conditions, fmt.Sprintf("%s = %s", quoteIdent(colName), s.Placeholder(plcCnt)))
				vals = append(vals, v)
				plcCnt++
			}
			sqlText += " WHERE " + strings.Join(conditions, " AND ")
		}
	}
	if orderby != "" {
		var validParts []string
		parts := strings.Fields(orderby)
		for _, part := range parts {
			cleanPart := strings.TrimSuffix(part, ",")
			upper := strings.ToUpper(cleanPart)
			if upper == "ASC" || upper == "DESC" {
				validParts = append(validParts, upper)
				continue
			}
			isValidCol := false
			lowerPart := strings.ToLower(cleanPart)
			for _, col := range s.Table.Columns {
				if strings.ToLower(col.ColumnName) == lowerPart || strings.ToLower(col.PascalName) == lowerPart {
					validParts = append(validParts, col.ColumnName)
					isValidCol = true
					break
				}
			}
			if !isValidCol {
				return nil, fmt.Errorf("invalid order by column: %s", cleanPart)
			}
		}
		if len(validParts) > 0 {
			sqlText += " ORDER BY " + strings.Join(validParts, " ")
		}
	}
	rows, err := s.Client.Query(ctx, sqlText, vals...)
	if err != nil {
		return nil, fmt.Errorf("failed to run query: %w", err)
	}
	defer rows.Close()

	fieldDescs := rows.FieldDescriptions()
	colNames := make([]string, len(fieldDescs))
	for i, fd := range fieldDescs {
		colNames[i] = fd.Name
	}

	scanDest := make([]any, len(colNames))
	var results []any
	rowVals := make([]any, len(colNames))
	for i := range rowVals {
		scanDest[i] = &rowVals[i]
	}
	for rows.Next() {
		if err := rows.Scan(scanDest...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		rowMap := make(map[string]any)
		for i := range colNames {
			jsonName := s.Table.Columns[i].PascalName
			rowMap[jsonName] = rowVals[i]
		}
		rowMap["op_code"] = "R"
		results = append(results, rowMap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read rows: %w", err)
	}
	return results, nil
}

func (s *TableServicePgsql) InsertSingle(ctx context.Context, partnerID int64, item any) (int64, error) {
	var args []any
	hasSequence := false
	for _, col := range s.Table.Columns {
		if col.HasDefault && col.DataType == model.DT_TIME {
			continue
		}
		if col.SequenceName != "" {
			hasSequence = true
			continue
		}
		if !s.Table.PartnerSpecific || col.ColumnName != "partner_id" {
			args = append(args, s.ExtractValue(item, col))
		} else {
			args = append(args, partnerID)
		}
	}
	if hasSequence {
		var id int64
		err := s.Client.QueryRow(ctx, s.sqlInsertItem, args...).Scan(&id)
		if err != nil {
			return -1, fmt.Errorf("failed to insert record: %w", err)
		}
		return id, nil
	}
	_, err := s.Client.Exec(ctx, s.sqlInsertItem, args...)
	return -1, err
}

// Insert writes one row (when item is a scalar) or many (when item is
// a slice) and returns the sequence-assigned ids. Tables without a
// sequence return an empty slice rather than `[-1]` (P1-43) so
// callers can distinguish "row inserted, no id" from "row inserted
// with an int64 id".
func (s *TableServicePgsql) Insert(ctx context.Context, partnerID int64, userID int, item any) ([]int64, error) {
	if !s.CheckPermission(ctx, userID, "INSERT") {
		return nil, fmt.Errorf("permission denied: INSERT on table %s", s.Table.TableName)
	}
	val := reflect.ValueOf(item)
	if val.Kind() != reflect.Slice {
		id, err := s.InsertSingle(ctx, partnerID, item)
		if err != nil {
			return nil, err
		}
		if id < 0 {
			// No sequence on this table — return an empty slice so
			// callers don't propagate the -1 sentinel into row writes.
			return nil, nil
		}
		return []int64{id}, nil
	}
	if val.Len() == 0 {
		return nil, nil
	}
	var results []int64
	for i := 0; i < val.Len(); i++ {
		id, err := s.InsertSingle(ctx, partnerID, val.Index(i).Interface())
		if err != nil {
			return nil, err
		}
		if id >= 0 {
			results = append(results, id)
		}
	}
	return results, nil
}

func (s *TableServicePgsql) Update(ctx context.Context, userID int, item any) error {
	if !s.CheckPermission(ctx, userID, "UPDATE") {
		return fmt.Errorf("permission denied: UPDATE on table %s", s.Table.TableName)
	}
	vals := make([]any, 0, len(s.Table.Columns))
	for _, col := range s.Table.Columns {
		isId := false
		for _, id := range s.Table.Keys {
			if col.ColumnName == id.ColumnName {
				isId = true
				break
			}
		}
		if !isId {
			vals = append(vals, s.ExtractValue(item, col))
		}
	}
	for _, id := range s.Table.Keys {
		tempCol := &model.TableColumn{
			ColumnName: id.ColumnName,
			PascalName: id.PascalName,
		}
		vals = append(vals, s.ExtractValue(item, tempCol))
	}
	_, err := s.Client.Exec(ctx, s.sqlUpdateByID, vals...)
	return err
}

func (s *TableServicePgsql) Delete(ctx context.Context, partnerID int64, userID int, where map[string]any) error {
	if !s.CheckPermission(ctx, userID, "DELETE") {
		return fmt.Errorf("permission denied: DELETE on table %s", s.Table.TableName)
	}
	if s.Table.PartnerSpecific {
		if where == nil {
			where = make(map[string]any)
		}
		// See the matching note in Get above. Same overwrite-vs-fallback
		// distinction: caller-supplied `partner_id` in `where` (e.g. from
		// a child-relation cascade) must be preserved, not coerced to the
		// session's partner.
		if _, set := where["partner_id"]; !set {
			where["partner_id"] = partnerID
		}
	}
	if len(where) == 0 {
		return fmt.Errorf("filter cannot be empty for delete operations")
	}
	var vals []any
	var sqlText string
	if len(where) == len(s.Table.Keys) && len(where) > 0 {
		match := true
		sortedVals := make([]any, len(s.Table.Keys))
		for i, col := range s.Table.Keys {
			if val, ok := where[col.ColumnName]; ok {
				sortedVals[i] = val
			} else {
				match = false
				break
			}
		}
		if match {
			sqlText = s.sqlDeleteByID
			vals = sortedVals
		}
	}
	if sqlText == "" {
		var conditions []string
		plcCnt := 1
		for k, v := range where {
			colName, ok := s.resolveColumnName(k)
			if !ok {
				return fmt.Errorf("invalid filter column: %s", k)
			}
			conditions = append(conditions, fmt.Sprintf("%s = %s", quoteIdent(colName), s.Placeholder(plcCnt)))
			vals = append(vals, v)
			plcCnt++
		}
		sqlText = "DELETE FROM " + s.quotedTable() + " WHERE " + strings.Join(conditions, " AND ")
	}
	_, err := s.Client.Exec(ctx, sqlText, vals...)
	return err
}

func (s *TableServicePgsql) Post(ctx context.Context, partnerID int64, userID int, data ...any) error {
	if len(data) == 0 {
		return nil
	}
	if s.Table == nil {
		return fmt.Errorf("table not defined")
	}
	for _, item := range data {
		itemVal := reflect.ValueOf(item)
		isMap := itemVal.Kind() == reflect.Map
		filter := make(map[string]any)
		for _, id := range s.Table.Keys {
			if isMap {
				m := item.(map[string]any)
				if v, ok := m[id.PascalName]; ok {
					filter[id.ColumnName] = v
				} else if v, ok := m[id.ColumnName]; ok {
					filter[id.ColumnName] = v
				}
			} else {
				filter[id.ColumnName] = itemVal.FieldByName(id.PascalName).Interface()
			}
		}
		existing, err := s.Get(ctx, partnerID, userID, filter, "")
		if err != nil {
			return fmt.Errorf("failed to check record status: %w", err)
		}
		if len(existing) > 0 {
			if err := s.Update(ctx, userID, item); err != nil {
				return fmt.Errorf("failed to update record: %w", err)
			}
		} else {
			if _, err := s.Insert(ctx, partnerID, userID, item); err != nil {
				return fmt.Errorf("failed to insert record: %w", err)
			}
		}
	}
	return nil
}
