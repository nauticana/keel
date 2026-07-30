package rest

import (
	"context"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

func pageTable() *model.TableDefinition {
	idCol := &model.TableColumn{ColumnName: "id", PascalName: "Id", IsKey: true}
	secretCol := &model.TableColumn{ColumnName: "token", PascalName: "Token", DisplayMode: model.DisplaySecret}
	return &model.TableDefinition{
		TableName: "widget",
		Columns:   []*model.TableColumn{idCol, secretCol},
		Keys:      []*model.TableColumn{idCol},
	}
}

func records(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = map[string]any{"Id": int64(i + 1), "Token": "secret"}
	}
	return out
}

// legacyTableService implements only port.TableService — the shape a downstream
// project's custom implementation has today.
type legacyTableService struct {
	port.TableService
	table *model.TableDefinition
	rows  []any
	order string
	calls int
}

func (s *legacyTableService) GetTable() *model.TableDefinition { return s.table }

func (s *legacyTableService) Get(_ context.Context, _ int64, _ int, _ map[string]any, order string) ([]any, error) {
	s.calls++
	s.order = order
	return s.rows, nil
}

// pagedTableService also implements the optional capability.
type pagedTableService struct {
	legacyTableService
	gotPage port.PageRequest
	total   int
}

func (s *pagedTableService) GetPage(_ context.Context, _ int64, _ int, _ map[string]any, page port.PageRequest) ([]any, int, error) {
	s.gotPage = page
	return s.rows, s.total, nil
}

// TestListPage_FallsBackForTableServiceWithoutCapability is the compatibility
// guarantee: a TableService that predates PagedTableService keeps working, with
// the same slice-after-read behavior callers had before.
func TestListPage_FallsBackForTableServiceWithoutCapability(t *testing.T) {
	svc := &legacyTableService{table: pageTable(), rows: records(25)}
	api := &RelationAPI{DataService: svc}

	items, total, err := api.ListPage(context.Background(), 1, 2, nil,
		port.PageRequest{Limit: 10, Offset: 20, OrderBy: "id"})
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	if len(items) != 5 {
		t.Fatalf("items = %d, want the 5-row tail of 25", len(items))
	}
	if total != 25 {
		t.Fatalf("total = %d, want 25", total)
	}
	if svc.order != "id" {
		t.Errorf("order = %q, want it forwarded to the fallback read", svc.order)
	}
	if _, leaked := items[0].(map[string]any)["Token"]; leaked {
		t.Error("secret column survived the fallback path")
	}
}

// TestListPage_FallbackImposesTotalOrder — the fallback must tie-break on the
// primary key too. Forwarding ?order= unchanged left custom TableService
// implementations paging nondeterministically whenever the caller's ordering was
// absent or non-unique, which is exactly the defect the capability path fixes.
func TestListPage_FallbackImposesTotalOrder(t *testing.T) {
	cases := []struct {
		name  string
		order string
		want  string
	}{
		{name: "no caller ordering", order: "", want: "id"},
		{name: "non-unique caller ordering", order: "token DESC", want: "token DESC, id"},
		{name: "already keyed", order: "id", want: "id"},
		{name: "already keyed by pascal name", order: "Id DESC", want: "Id DESC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := &legacyTableService{table: pageTable(), rows: records(3)}
			api := &RelationAPI{DataService: svc}
			if _, _, err := api.ListPage(context.Background(), 1, 2, nil,
				port.PageRequest{Limit: 2, OrderBy: c.order}); err != nil {
				t.Fatalf("ListPage: %v", err)
			}
			if svc.order != c.want {
				t.Errorf("order = %q, want %q", svc.order, c.want)
			}
		})
	}
}

// TestListPage_FallbackWithoutTableDefinition — a nil table definition must not
// panic on the way to building the tie-break.
func TestListPage_FallbackWithoutTableDefinition(t *testing.T) {
	svc := &legacyTableService{table: nil, rows: records(2)}
	api := &RelationAPI{DataService: svc}
	items, total, err := api.ListPage(context.Background(), 1, 2, nil, port.PageRequest{Limit: 5})
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	if len(items) != 2 || total != 2 {
		t.Fatalf("items = %d, total = %d; want 2 and 2", len(items), total)
	}
	if svc.order != "" {
		t.Errorf("order = %q, want empty with no key columns to append", svc.order)
	}
}

// TestListPage_UsesCapabilityWhenAvailable — bounds go to the data layer and the
// total comes back from it, with no in-memory slicing on top.
func TestListPage_UsesCapabilityWhenAvailable(t *testing.T) {
	svc := &pagedTableService{
		legacyTableService: legacyTableService{table: pageTable(), rows: records(10)},
		total:              137,
	}
	api := &RelationAPI{DataService: svc}

	page := port.PageRequest{Limit: 10, Offset: 30, OrderBy: "id DESC"}
	items, total, err := api.ListPage(context.Background(), 1, 2, nil, page)
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	if svc.gotPage != page {
		t.Fatalf("GetPage received %+v, want %+v", svc.gotPage, page)
	}
	if svc.calls != 0 {
		t.Error("capability path must not also run the unbounded Get")
	}
	if len(items) != 10 || total != 137 {
		t.Fatalf("items = %d, total = %d; want 10 and 137", len(items), total)
	}
	if _, leaked := items[0].(map[string]any)["Token"]; leaked {
		t.Error("secret column survived the capability path")
	}
}

func TestPageRequestSlice(t *testing.T) {
	items := records(5)
	cases := []struct {
		page port.PageRequest
		want int
	}{
		{page: port.PageRequest{Limit: 2, Offset: 0}, want: 2},
		{page: port.PageRequest{Limit: 2, Offset: 4}, want: 1},
		{page: port.PageRequest{Limit: 2, Offset: 5}, want: 0},
		{page: port.PageRequest{Limit: 2, Offset: 99}, want: 0},
		{page: port.PageRequest{Limit: 0, Offset: 1}, want: 4},
		{page: port.PageRequest{Limit: 10, Offset: -3}, want: 5},
	}
	for _, c := range cases {
		if got := len(c.page.Slice(items)); got != c.want {
			t.Errorf("Slice(%+v) = %d rows, want %d", c.page, got, c.want)
		}
	}
}
