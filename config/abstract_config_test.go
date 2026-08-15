package config

import (
	"context"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type configTestQueryService struct {
	port.QueryService
	args []any
	rows [][]any
}

func (s *configTestQueryService) Query(_ context.Context, _ string, args ...any) (*model.QueryResult, error) {
	s.args = args
	return &model.QueryResult{Rows: s.rows}, nil
}

type configTestDatabase struct {
	port.DatabaseRepository
	queryService port.QueryService
}

func (d *configTestDatabase) GetQueryService(context.Context, map[string]string) port.QueryService {
	return d.queryService
}

func TestLoadRowsUsesExplicitNodeID(t *testing.T) {
	queryService := &configTestQueryService{rows: [][]any{{"value", "assigned", "default"}}}
	database := &configTestDatabase{queryService: queryService}

	rows, err := LoadRows(context.Background(), database, 37)
	if err != nil {
		t.Fatalf("LoadRows: %v", err)
	}
	if len(queryService.args) != 1 || queryService.args[0] != 37 {
		t.Fatalf("query args = %#v, want [37]", queryService.args)
	}
	if got := rows["value"]; got != (ConfigRow{Value: "assigned", Default: "default"}) {
		t.Fatalf("rows[value] = %#v", got)
	}
}

func TestLoadRowsEmptyCatalogFails(t *testing.T) {
	database := &configTestDatabase{queryService: &configTestQueryService{}}
	if _, err := LoadRows(context.Background(), database, 0); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("want empty-catalog error, got: %v", err)
	}
}
