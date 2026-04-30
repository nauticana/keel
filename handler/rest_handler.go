package handler

import (
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/rest"
)

type RestHandler struct {
	AbstractHandler
	Api rest.RestAPI

	// columnByPascal is a lazy lookup map from PascalName → *TableColumn,
	// built once on first request and reused across every Get / List
	// call (v0.4.4 perf). The previous implementation walked every
	// column on every filter key per request — O(filter × columns)
	// for what should be O(filter) lookups. For wide tables (50+
	// cols) under load this added up.
	columnByPascalOnce sync.Once
	columnByPascal     map[string]*model.TableColumn
}

func queryParamsToFilter(r *http.Request) map[string]string {
	result := make(map[string]string)
	for k, v := range r.URL.Query() {
		if len(v) > 0 && v[0] != "" {
			result[k] = v[0]
		}
	}
	return result
}

// columnLookup returns the cached PascalName → *TableColumn map,
// constructing it lazily on first use. Concurrent first-callers
// converge via sync.Once so the build runs exactly once.
func (h *RestHandler) columnLookup() map[string]*model.TableColumn {
	h.columnByPascalOnce.Do(func() {
		tableDef := h.Api.GetTable()
		if tableDef == nil {
			h.columnByPascal = map[string]*model.TableColumn{}
			return
		}
		m := make(map[string]*model.TableColumn, len(tableDef.Columns))
		for _, col := range tableDef.Columns {
			m[col.PascalName] = col
		}
		h.columnByPascal = m
	})
	return h.columnByPascal
}

func (h *RestHandler) castFilterValues(filter map[string]string) (map[string]any, error) {
	typedFilter := make(map[string]any)
	if len(filter) == 0 {
		return typedFilter, nil
	}
	cols := h.columnLookup()
	for k, v := range filter {
		matchedCol, ok := cols[k]
		if !ok {
			continue
		}
		colName := matchedCol.ColumnName
		switch matchedCol.DataType {
		case "integer":
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse filter value '%s' for key '%s' as integer: %w", v, k, err)
			}
			typedFilter[colName] = i
		case "float":
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse filter value '%s' for key '%s' as float: %w", v, k, err)
			}
			typedFilter[colName] = f
		case "boolean":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("failed to parse filter value '%s' for key '%s' as boolean: %w", v, k, err)
			}
			typedFilter[colName] = b
		case "timestamp":
			d, err := time.Parse("2006-01-02 15:04:05", v)
			if err != nil {
				d, err = time.Parse("2006-01-02", v)
				if err != nil {
					return nil, fmt.Errorf("failed to parse filter value '%s' for key '%s' as date: %w", v, k, err)
				}
			}
			typedFilter[colName] = d
		default:
			typedFilter[colName] = v
		}
	}
	return typedFilter, nil
}

// MaxListPageSize is the absolute upper bound on rows a single List
// response can carry — even if the caller asks for more, we cap.
// Closes the un-bounded list DoS surface flagged by P0-30 / P1-36.
const MaxListPageSize = 1000

// DefaultListPageSize applies when the caller omits ?limit=. Chosen
// to match what most UI grids actually render in one page.
const DefaultListPageSize = 100

// extractPagination reads ?limit= and ?offset= from the URL,
// applying defaults and the hard cap. Removes both keys from the
// filter map so they don't leak into the SQL WHERE clause downstream.
func extractPagination(filter map[string]string) (limit, offset int) {
	limit = DefaultListPageSize
	offset = 0
	if v, ok := filter["limit"]; ok {
		delete(filter, "limit")
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v, ok := filter["offset"]; ok {
		delete(filter, "offset")
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	if limit > MaxListPageSize {
		limit = MaxListPageSize
	}
	return limit, offset
}

// extractOrder reads ?order= from the URL and removes the key from
// the filter map so it doesn't leak into the SQL WHERE clause. The
// underlying TableService validates the resulting string against its
// column whitelist (ASC / DESC / column-name only) and rejects
// anything else as a 400, so passing untrusted query input here is
// safe — the data layer is the gatekeeper. (P2-22.)
func extractOrder(filter map[string]string) string {
	v := filter["order"]
	delete(filter, "order")
	return strings.TrimSpace(v)
}

// applyPagination slices a result set to (offset, offset+limit). The
// underlying List() still pulls everything from the DB — a proper SQL
// LIMIT push-down would require widening the rest.RestAPI signature
// — but the cap here at least bounds what crosses the wire and what
// the JSON encoder buffers.
func applyPagination(results []any, limit, offset int) []any {
	if offset >= len(results) {
		return []any{}
	}
	end := offset + limit
	if end > len(results) {
		end = len(results)
	}
	return results[offset:end]
}

// Get serves a single-record (or filtered-collection) read. Requires
// an authenticated session — keel-side handler rejects -1 sentinels
// so a misconfigured route can never serve unauth'd reads.
func (h *RestHandler) Get(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	filterStr := queryParamsToFilter(r)
	order := extractOrder(filterStr)
	filter, err := h.castFilterValues(filterStr)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	results, err := h.Api.Get(r.Context(), session.PartnerId, session.Id, filter, order)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "internal server error")
		return
	}
	if results == nil {
		results = []any{}
	}
	common.WriteJSON(w, http.StatusOK, results)
}

// List serves a collection read with pagination via ?limit= and
// ?offset=. Optional ?order= takes column names with ASC / DESC
// keywords; the data layer rejects anything outside the table's
// declared columns, so the value is safe to surface from query
// parameters (P2-22). The default limit is DefaultListPageSize and
// is hard-capped at MaxListPageSize to prevent unbounded DB scans
// driving memory / network DoS.
func (h *RestHandler) List(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	filterStr := queryParamsToFilter(r)
	limit, offset := extractPagination(filterStr)
	order := extractOrder(filterStr)
	filter, err := h.castFilterValues(filterStr)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	results, err := h.Api.List(r.Context(), session.PartnerId, session.Id, filter, order)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "internal server error")
		return
	}
	if results == nil {
		results = []any{}
	}
	page := applyPagination(results, limit, offset)
	common.WriteJSON(w, http.StatusOK, map[string]any{
		"items":  page,
		"limit":  limit,
		"offset": offset,
		"total":  len(results),
	})
}

func (h *RestHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodDelete, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	filterStr := queryParamsToFilter(r)
	if len(filterStr) == 0 {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "delete method cannot be called without filter")
		return
	}
	filter, err := h.castFilterValues(filterStr)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	if err := h.Api.Delete(r.Context(), session.PartnerId, session.Id, filter); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "internal server error")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"message": "deleted"})
}

// Post creates one or more records. Returns 201 Created with the
// items echoed back so the client can read sequence-assigned ids.
// (Previously returned 200, which obscures the create vs update
// distinction on the wire.)
func (h *RestHandler) Post(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	var input any
	if !h.ReadRequest(w, r, &input) {
		return
	}
	var items []any
	val := reflect.ValueOf(input)
	if val.Kind() == reflect.Slice {
		for i := 0; i < val.Len(); i++ {
			items = append(items, val.Index(i).Interface())
		}
	} else {
		items = append(items, input)
	}
	if len(items) == 0 {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "no items provided in the request body")
		return
	}
	if err := h.Api.Post(r.Context(), session.PartnerId, session.Id, items...); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "internal server error")
		return
	}
	common.WriteJSON(w, http.StatusCreated, items)
}
