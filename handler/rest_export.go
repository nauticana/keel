package handler

import (
	"cmp"
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
)

// Export streams the rows List would return, filtered and ordered the same
// way, as text/csv with a header of column captions. It requires TABLE EXPORT
// on the table besides the SELECT the read enforces, returns at most
// max_export_rows rows, and sets X-Export-Truncated when more matched.
func (h *RestHandler) Export(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	table := h.Api.GetTable()
	if table == nil {
		h.WriteError(w, http.StatusNotFound, "Not Found", "unknown table")
		return
	}
	if allowed, _ := h.Api.Relations.DataService.CheckPermission(r.Context(), model.UserPrincipal(session.Id), "EXPORT"); !allowed {
		h.WriteError(w, http.StatusForbidden, "Forbidden", "missing permission TABLE/EXPORT on "+table.TableName)
		return
	}
	filterStr := queryParamsToFilter(r)
	order := extractOrder(filterStr)
	filter, err := h.castFilterValues(filterStr)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	limit := config.Config().MaxExportRows
	items, _, err := h.Api.ListPage(r.Context(), session.PartnerId, session.Id, filter,
		model.PageRequest{Limit: limit + 1, OrderBy: order})
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	if len(items) > limit {
		items = items[:limit]
		w.Header().Set("X-Export-Truncated", "true")
	}
	records := make([]map[string]any, len(items))
	for i, item := range items {
		record, ok := item.(map[string]any)
		if !ok {
			h.WriteServiceError(w, r, fmt.Errorf("rest export: unexpected row type %T", item))
			return
		}
		records[i] = record
	}
	var columns []*model.TableColumn
	var header []string
	for _, col := range table.Columns {
		if col.DisplayMode == model.DisplaySecret {
			continue
		}
		columns = append(columns, col)
		header = append(header, csvCell(cmp.Or(col.Caption, col.ColumnName)))
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+table.TableName+`.csv"`)
	out := csv.NewWriter(w)
	_ = out.Write(header)
	row := make([]string, len(columns))
	for _, record := range records {
		for i, col := range columns {
			row[i] = csvCell(csvValue(record[col.PascalName]))
		}
		_ = out.Write(row)
	}
	out.Flush()
	if h.Journal != nil {
		h.Journal.Info(fmt.Sprintf("export %s: %d rows by user %d of partner %d", table.TableName, len(items), session.Id, session.PartnerId))
	}
	if err := out.Error(); err != nil && h.Journal != nil {
		h.Journal.Warning(fmt.Sprintf("export %s: write: %v", table.TableName, err))
	}
}

func csvValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case time.Time:
		return t.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprint(v)
	}
}

// csvCell neutralizes a value a spreadsheet would run as a formula.
func csvCell(s string) string {
	for _, r := range s {
		if strings.ContainsRune(" \t\r\n", r) {
			continue
		}
		if strings.ContainsRune("=+-@", r) {
			return "'" + s
		}
		break
	}
	return s
}
