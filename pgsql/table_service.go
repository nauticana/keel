package pgsql

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// scopePartnerFilter pins a PartnerSpecific query to the caller's partner: a
// foreign partner_id is coerced to the caller's scope (to 0 — no rows — for a
// user with no partner) unless the caller holds a global role or is a trusted
// system caller (no user AND no partner scope). So API-key callers (userID==0,
// partnerID>0) can't read another tenant via ?partner_id, and a user with no
// partner (e.g. a cross-partner rider) can't read a partner through generic
// CRUD — that access belongs in a custom owner-scoped (user_id) handler.
func scopePartnerFilter(where map[string]any, partnerID int64, userID int, globalRole bool) {
	supplied, set := where["partner_id"]
	switch {
	case !set:
		where["partner_id"] = partnerID
	case globalRole:
		// cross-partner role: honor the supplied partner_id.
	case userID <= 0 && partnerID <= 0:
		// trusted system caller with no scope (worker/job): honor the filter.
	case common.AsInt64(supplied) != partnerID:
		where["partner_id"] = partnerID
	}
}

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

// skipInsertCol reports whether a column is omitted from generated INSERTs.
// Explicit display modes win over the legacy timestamp-default heuristic, so a
// D/I column with a defaulted timestamp is still written. Sequence handling is
// separate (the caller checks SequenceName after this).
func skipInsertCol(col *model.TableColumn) bool {
	switch col.DisplayMode {
	case model.DisplayHidden, model.DisplayReadonly, model.DisplayUpdateStamp, model.DisplaySecret:
		return true // system-managed: DB default / trigger fills it (U stamps on UPDATE only; S owned by dedicated flows)
	case "":
		return col.HasDefault && col.DataType == model.DT_TIME // unmoded audit timestamps
	}
	return false
}

// skipUpdateCol reports whether a column is omitted from generated UPDATE SETs
// (beyond keys and the UserSpecific user_id pin, handled separately).
// updateStampKind classifies a 'U' audit-stamp column by its target value on
// UPDATE: stampNow → set now() inline (timestamp), stampUser → bind the
// updater's user_id (integer). stampNone = not a usable stamp (non-U, or an
// unsupported type) and is treated as not-updatable, like 'R'.
const (
	stampNone = iota
	stampNow
	stampUser
)

func updateStampKind(col *model.TableColumn) int {
	if col.DisplayMode != model.DisplayUpdateStamp {
		return stampNone
	}
	switch col.DataType {
	case model.DT_TIME:
		return stampNow
	case model.DT_INT:
		return stampUser
	}
	return stampNone
}

func skipUpdateCol(col *model.TableColumn) bool {
	switch col.DisplayMode {
	case model.DisplayHidden, model.DisplayReadonly, model.DisplayInsertOnly, model.DisplaySecret:
		return true
	case model.DisplayUpdateStamp:
		return updateStampKind(col) == stampNone // unsupported type → not updatable
	}
	return false
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
		// user_id / partner_id are immutable scope columns — excluded from the
		// UPDATE SET so ownership/tenancy can't be reassigned via CRUD. Update()
		// depends on these exclusions: its value loop applies the same skips.
		if s.Table.UserSpecific && col.ColumnName == "user_id" {
			continue
		}
		if s.Table.PartnerSpecific && col.ColumnName == "partner_id" {
			continue
		}
		// R/H/I columns are not user-updatable (must stay in sync with the
		// Update() value-binding loop below).
		if skipUpdateCol(col) {
			continue
		}
		// 'U' audit stamp: keel sets the value, not the caller — now() inline
		// for timestamps, a bound user_id placeholder for integers.
		switch updateStampKind(col) {
		case stampNow:
			updateSet = append(updateSet, fmt.Sprintf("%s = now()", quoteIdent(col.ColumnName)))
			continue
		case stampUser:
			updateSet = append(updateSet, fmt.Sprintf("%s = %s", quoteIdent(col.ColumnName), s.Placeholder(plcCnt)))
			plcCnt++
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
	// INSERT SQL is built per row in InsertSingle so a cleared value on a
	// column with a DB default can emit DEFAULT instead of binding NULL.
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
	allowed, ownScope := false, false
	if userID > 0 {
		allowed, ownScope = s.CheckPermission(ctx, userID, "SELECT")
		if !allowed {
			return nil, model.NewForbidden(fmt.Sprintf("No authorization for SELECT on %s", s.Table.TableName))
		}
	}
	var sqlText string
	var vals []any

	// PartnerUserScoped is the user_account-style flag: rows are global
	// (no partner_id column) and access must be JOIN-filtered through
	// partner_user. Compute the gate once here so both the by-key fast
	// path and the generic WHERE-builder branch reuse the same answer.
	// Bypass for global-trust roles (SUPER / BUSINESS_ADMIN / etc.) —
	// IsGlobalRole fails closed, so a query failure during the role
	// check applies the stricter scope rather than skipping it.
	applyPartnerUserScope := s.Table.PartnerUserScoped && userID > 0 && !s.IsGlobalRole(ctx, userID)

	if s.Table.PartnerSpecific {
		if where == nil {
			where = make(map[string]any)
		}
		scopePartnerFilter(where, partnerID, userID, s.IsGlobalRole(ctx, userID))
	}
	// Apply user_id filter only when the caller's permission is broad
	// (wildcard match). An explicit per-table grant — typical of admin
	// roles like FINANCE_ADMIN — leaves ownScope=false and lets the
	// admin read across all owners.
	if s.Table.UserSpecific && userID > 0 && ownScope {
		if where == nil {
			where = make(map[string]any)
		}
		// Owner-lock: force `user_id = caller` so a caller-supplied
		// ?user_id=<victim> cannot preserve a foreign scope. Force, not
		// fall back — a wildcard-grant caller only ever reads its own rows,
		// and the cascade's propagated user_id already equals the session's.
		where["user_id"] = userID
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
			// By-key fast path on a PartnerUserScoped table still needs
			// the partner_user gate — a PARTNER_ADMIN supplying a known
			// user_id from another partner would otherwise round-trip the
			// row. Append the subquery and the session's partner as the
			// next positional placeholder. The primary key on
			// user_account is single-column (`id`), so the join condition
			// targets the first (and only) key.
			if applyPartnerUserScope {
				keyCol := s.Table.Keys[0].ColumnName
				sqlText += fmt.Sprintf(" AND %s IN (SELECT user_id FROM %s WHERE partner_id = %s)",
					quoteIdent(keyCol), quoteIdent("partner_user"), s.Placeholder(len(vals)+1))
				vals = append(vals, partnerID)
			}
		}
	}
	if sqlText == "" {
		sqlText = s.sqlSelectAll
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
		// Generic-WHERE branch: same partner_user gate as the by-key
		// fast path, expressed as an additional condition. Joins the
		// subquery on the table's primary key (id).
		if applyPartnerUserScope {
			keyCol := s.Table.Keys[0].ColumnName
			conditions = append(conditions, fmt.Sprintf("%s IN (SELECT user_id FROM %s WHERE partner_id = %s)",
				quoteIdent(keyCol), quoteIdent("partner_user"), s.Placeholder(plcCnt)))
			vals = append(vals, partnerID)
		}
		if len(conditions) > 0 {
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
			// Strip pgx wrapper types (pgtype.Time/Date/Numeric/…) so JSON clients
			// get primitives, not "[object Object]". Matches QueryService.Query.
			rowMap[jsonName] = normalizeValue(rowVals[i])
		}
		rowMap["op_code"] = "R"
		results = append(results, rowMap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read rows: %w", err)
	}
	return results, nil
}

func (s *TableServicePgsql) InsertSingle(ctx context.Context, partnerID int64, userID int, item any) (int64, error) {
	var cols, vals []string
	var args []any
	hasSequence := false
	seqColumn := ""
	plc := 1
	for _, col := range s.Table.Columns {
		// R/H (and unmoded audit timestamps) are server-managed.
		if skipInsertCol(col) {
			continue
		}
		cols = append(cols, quoteIdent(col.ColumnName))
		if col.SequenceName != "" {
			hasSequence = true
			seqColumn = col.ColumnName
			vals = append(vals, fmt.Sprintf("nextval(%s)", quoteSQLString(col.SequenceName)))
			continue
		}
		var v any
		switch {
		case s.Table.PartnerSpecific && col.ColumnName == "partner_id":
			v = partnerID
		case s.Table.UserSpecific && col.ColumnName == "user_id" && userID > 0:
			// Force user_id = authenticated user. Ignore whatever the
			// caller supplied so a row owner can never be spoofed at
			// insert time. userID==0 (system / anonymous) keeps the
			// caller-supplied value as a safety hatch for backfills.
			v = userID
		default:
			v = s.ExtractValue(item, col)
		}
		// A cleared/missing value (nil) on a column that has a DB default emits
		// the SQL DEFAULT keyword so the default applies (e.g. NOT NULL ...
		// DEFAULT 0) rather than binding NULL and tripping the constraint.
		if v == nil && col.HasDefault {
			vals = append(vals, "DEFAULT")
			continue
		}
		vals = append(vals, s.Placeholder(plc))
		plc++
		args = append(args, v)
	}
	sql := "INSERT INTO " + s.quotedTable() + " (" + strings.Join(cols, ", ") + ") VALUES (" + strings.Join(vals, ", ") + ")"
	if hasSequence {
		sql += " RETURNING " + quoteIdent(seqColumn)
		var id int64
		if err := s.Client.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			return -1, fmt.Errorf("failed to insert record: %w", err)
		}
		return id, nil
	}
	_, err := s.Client.Exec(ctx, sql, args...)
	return -1, err
}

// Insert writes one row (when item is a scalar) or many (when item is
// a slice) and returns the sequence-assigned ids. Tables without a
// sequence return an empty slice rather than `[-1]` (P1-43) so
// callers can distinguish "row inserted, no id" from "row inserted
// with an int64 id".
func (s *TableServicePgsql) Insert(ctx context.Context, partnerID int64, userID int, item any) ([]int64, error) {
	allowed, _ := s.CheckPermission(ctx, userID, "INSERT")
	if !allowed {
		return nil, model.NewForbidden(fmt.Sprintf("No authorization for INSERT on %s", s.Table.TableName))
	}
	val := reflect.ValueOf(item)
	// UserSpecific writes are STRICT: the user_id column is force-set
	// to the authenticated caller regardless of the caller's scope (an
	// admin's explicit grant doesn't bypass the owner-pin). Admins
	// that need to seed rows on behalf of another user must use a
	// custom service-layer handler that writes raw SQL — generic CRUD
	// on UserSpecific tables is owner-locked to prevent spoofing.
	// userID == 0 (system / backfill) keeps InsertSingle's
	// `userID > 0` guard inactive so the caller-supplied value is
	// used — that's the safety hatch for one-off migrations.
	if val.Kind() != reflect.Slice {
		id, err := s.InsertSingle(ctx, partnerID, userID, item)
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
		id, err := s.InsertSingle(ctx, partnerID, userID, val.Index(i).Interface())
		if err != nil {
			return nil, err
		}
		if id >= 0 {
			results = append(results, id)
		}
	}
	return results, nil
}

func (s *TableServicePgsql) Update(ctx context.Context, partnerID int64, userID int, item any) error {
	allowed, _ := s.CheckPermission(ctx, userID, "UPDATE")
	if !allowed {
		return model.NewForbidden(fmt.Sprintf("No authorization for UPDATE on %s", s.Table.TableName))
	}
	if s.sqlUpdateByID == "" {
		return nil // no updatable columns
	}
	// Tenant/owner scoping mirrors Get/Delete: append partner_id / user_id
	// predicates so a caller who knows a foreign PK gets ROW_COUNT=0. Global
	// roles and trusted system callers (no user, no partner) bypass.
	applyPartner := s.Table.PartnerSpecific && !(userID <= 0 && partnerID <= 0) && !s.IsGlobalRole(ctx, userID)
	useUserGuard := s.Table.UserSpecific && userID > 0
	vals := make([]any, 0, len(s.Table.Columns))
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
		// Init excluded the immutable scope columns (user_id / partner_id)
		// from the SET; skip them here too so the value list and the
		// placeholder list stay in sync.
		if s.Table.UserSpecific && col.ColumnName == "user_id" {
			continue
		}
		if s.Table.PartnerSpecific && col.ColumnName == "partner_id" {
			continue
		}
		if skipUpdateCol(col) {
			continue
		}
		// Mirror the SET-clause stamp handling: now() consumes no arg, a
		// user_id stamp binds the authenticated updater.
		switch updateStampKind(col) {
		case stampNow:
			continue
		case stampUser:
			vals = append(vals, userID)
			continue
		}
		vals = append(vals, s.ExtractValue(item, col))
	}
	for _, id := range s.Table.Keys {
		tempCol := &model.TableColumn{
			ColumnName: id.ColumnName,
			PascalName: id.PascalName,
		}
		vals = append(vals, s.ExtractValue(item, tempCol))
	}
	sqlText := s.sqlUpdateByID
	if applyPartner {
		sqlText += " AND " + quoteIdent("partner_id") + " = " + s.Placeholder(len(vals)+1)
		vals = append(vals, partnerID)
	}
	if useUserGuard {
		sqlText += " AND " + quoteIdent("user_id") + " = " + s.Placeholder(len(vals)+1)
		vals = append(vals, userID)
	}
	_, err := s.Client.Exec(ctx, sqlText, vals...)
	return err
}

func (s *TableServicePgsql) Delete(ctx context.Context, partnerID int64, userID int, where map[string]any) error {
	allowed, _ := s.CheckPermission(ctx, userID, "DELETE")
	if !allowed {
		return model.NewForbidden(fmt.Sprintf("No authorization for DELETE on %s", s.Table.TableName))
	}
	// PartnerUserScoped DELETE defense-in-depth: bar a PARTNER_ADMIN
	// from deleting a user_account belonging to another partner via a
	// crafted id. Same gate as Get; bypass for global-trust roles.
	applyPartnerUserScope := s.Table.PartnerUserScoped && userID > 0 && !s.IsGlobalRole(ctx, userID)
	if s.Table.PartnerSpecific {
		if where == nil {
			where = make(map[string]any)
		}
		scopePartnerFilter(where, partnerID, userID, s.IsGlobalRole(ctx, userID))
	}
	// UserSpecific DELETE is owner-locked unconditionally: even an admin's
	// explicit grant cannot remove another user's row via generic CRUD
	// (README behaviour matrix, Delete). Force `user_id = caller` so a
	// caller-supplied ?user_id=<victim> cannot widen the delete to another
	// owner's row. Cross-user deletes belong in custom handlers.
	if s.Table.UserSpecific && userID > 0 {
		if where == nil {
			where = make(map[string]any)
		}
		where["user_id"] = userID
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
			if applyPartnerUserScope {
				keyCol := s.Table.Keys[0].ColumnName
				sqlText += fmt.Sprintf(" AND %s IN (SELECT user_id FROM %s WHERE partner_id = %s)",
					quoteIdent(keyCol), quoteIdent("partner_user"), s.Placeholder(len(vals)+1))
				vals = append(vals, partnerID)
			}
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
		if applyPartnerUserScope {
			keyCol := s.Table.Keys[0].ColumnName
			conditions = append(conditions, fmt.Sprintf("%s IN (SELECT user_id FROM %s WHERE partner_id = %s)",
				quoteIdent(keyCol), quoteIdent("partner_user"), s.Placeholder(plcCnt)))
			vals = append(vals, partnerID)
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
			if err := s.Update(ctx, partnerID, userID, item); err != nil {
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

var _ port.TableService = (*TableServicePgsql)(nil)
