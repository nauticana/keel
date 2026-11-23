package rest

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nauticana/keel/schema"
)

func loadReports(header []any, series ...string) (*RestService, error) {
	rows := map[string][][]any{
		qRestReportHeader: {header},
		qRestReportParam:  {{"sales", 1, "from", "date", ""}, {"inactive", 1, "x", "string", ""}},
	}
	for _, column := range series {
		rows[qRestReportSeries] = append(rows[qRestReportSeries], []any{"sales", column})
	}
	rows[qRestReportSeries] = append(rows[qRestReportSeries], []any{"inactive", "ignored"})
	s := &RestService{qs: fakeReportQuery{rows: rows}}
	return s, s.loadReports(context.Background())
}

func TestLoadReportsCarriesChartColumns(t *testing.T) {
	s, err := loadReports([]any{"sales", "v1", "sales_by_month", "Sales", "B", "month"}, "revenue", "refunds")
	if err != nil {
		t.Fatal(err)
	}
	r := s.RestReports["sales"]
	if r.ChartKind != ChartBar || r.CategoryColumn != "month" || !reflect.DeepEqual(r.Series, []string{"revenue", "refunds"}) {
		t.Fatalf("chart = %s %q %v", r.ChartKind, r.CategoryColumn, r.Series)
	}
	if len(r.Params) != 1 || r.Params[0].Name != "from" {
		t.Fatalf("params = %v", r.Params)
	}
}

func TestLoadReportsWithoutChart(t *testing.T) {
	s, err := loadReports([]any{"sales", "v1", "sales_by_month", "Sales", "N", ""})
	if err != nil {
		t.Fatal(err)
	}
	if r := s.RestReports["sales"]; r.ChartKind != ChartNone || r.Series == nil || len(r.Series) != 0 {
		t.Fatalf("chart = %s %v", r.ChartKind, r.Series)
	}
}

func TestLoadReportsRefusesUndrawableChart(t *testing.T) {
	for name, tc := range map[string]struct {
		header []any
		series []string
		want   string
	}{
		"series without a chart": {[]any{"sales", "v1", "q", "d", "N", ""}, []string{"revenue"}, "has chart columns"},
		"unknown kind":           {[]any{"sales", "v1", "q", "d", "Z", "month"}, []string{"revenue"}, "unknown chart_kind"},
		"no category":            {[]any{"sales", "v1", "q", "d", "L", ""}, []string{"revenue"}, "no category_column"},
		"no series":              {[]any{"sales", "v1", "q", "d", "L", "month"}, nil, "no rest_report_series"},
		"pie with two series":    {[]any{"sales", "v1", "q", "d", "P", "month"}, []string{"revenue", "refunds"}, "a pie plots one"},
		"category as series":     {[]any{"sales", "v1", "q", "d", "B", "month"}, []string{"month"}, "repeats"},
		"repeated series":        {[]any{"sales", "v1", "q", "d", "B", "month"}, []string{"revenue", "revenue"}, "repeats"},
	} {
		if _, err := loadReports(tc.header, tc.series...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestChartKindsMatchSeed(t *testing.T) {
	seed, err := schema.ParseSeedFile("../schema/seed/core.yml")
	if err != nil {
		t.Fatal(err)
	}
	var seeded []string
	for _, st := range seed.Seeds {
		if st.Table != "constant_value" {
			continue
		}
		for _, row := range st.Rows {
			if row[0] == "chart_kind" {
				seeded = append(seeded, row[1].(string))
			}
		}
	}
	want := []string{string(ChartBar), string(ChartLine), string(ChartNone), string(ChartPie)}
	sort.Strings(seeded)
	if !reflect.DeepEqual(seeded, want) {
		t.Fatalf("seeded chart_kind codes = %v, Go has %v", seeded, want)
	}
}
