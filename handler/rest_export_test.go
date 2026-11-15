package handler

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/rest"
)

type exportTable struct {
	port.TableService
	export bool
	rows   int
	page   model.PageRequest
	where  map[string]any
}

func (t *exportTable) GetTable() *model.TableDefinition {
	return &model.TableDefinition{TableName: "lead", Columns: []*model.TableColumn{
		{ColumnName: "id", PascalName: "Id", DataType: model.DT_BIGINT},
		{ColumnName: "name", PascalName: "Name", Caption: "Full name"},
		{ColumnName: "token", PascalName: "Token", DisplayMode: model.DisplaySecret},
	}}
}

func (t *exportTable) CheckPermission(_ context.Context, _ model.Principal, action string) (bool, bool) {
	return action == "EXPORT" && t.export, true
}

func (t *exportTable) GetPage(_ context.Context, _ int64, _ int, where map[string]any, page model.PageRequest) ([]any, int, error) {
	t.page, t.where = page, where
	items := []any{}
	for i := range min(t.rows, page.Limit) {
		items = append(items, map[string]any{"Id": int64(i + 1), "Name": "=HYPERLINK(1)", "Token": "secret"})
	}
	return items, t.rows, nil
}

func TestRestExport(t *testing.T) {
	saved := config.Config().MaxExportRows
	config.Config().MaxExportRows = 2
	t.Cleanup(func() { config.Config().MaxExportRows = saved })
	table := &exportTable{export: true, rows: 3}
	h := &RestHandler{Api: rest.RestAPI{Relations: rest.RelationAPI{DataService: table}}}
	call := func(session *model.UserSession) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/lead/export?Id=1&order=name", nil)
		if session != nil {
			stashSession(r, session)
		}
		w := httptest.NewRecorder()
		h.Export(w, r)
		return w
	}
	w := call(&model.UserSession{Id: 3, PartnerId: 7})
	if w.Code != http.StatusOK || w.Header().Get("X-Export-Truncated") != "true" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("status %d headers %v", w.Code, w.Header())
	}
	if table.page.Limit != 3 || table.page.OrderBy != "name" || table.where["id"] != int64(1) {
		t.Fatalf("read page %+v where %v", table.page, table.where)
	}
	records, err := csv.NewReader(w.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"id", "Full name"}, {"1", "'=HYPERLINK(1)"}, {"2", "'=HYPERLINK(1)"}}
	if len(records) != len(want) || strings.Join(records[0], ",") != "id,Full name" || records[1][1] != want[1][1] {
		t.Fatalf("csv = %q", records)
	}
	for cell, want := range map[string]string{" \t=1+1": "' \t=1+1", "\r\n@x": "'\r\n@x", "a=b": "a=b", "": "", "  ": "  "} {
		if got := csvCell(cell); got != want {
			t.Fatalf("csvCell(%q) = %q, want %q", cell, got, want)
		}
	}
	table.export = false
	if w := call(&model.UserSession{Id: 3, PartnerId: 7}); w.Code != http.StatusForbidden {
		t.Fatalf("without EXPORT = %d", w.Code)
	}
	if w := call(nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("without session = %d", w.Code)
	}
}

func TestReservedExportActionName(t *testing.T) {
	if !model.IsReservedActionName("Export") {
		t.Fatal("export must be reserved")
	}
}
