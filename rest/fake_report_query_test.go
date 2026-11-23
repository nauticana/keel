package rest

import (
	"context"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// fakeReportQuery answers each named query with its rows.
type fakeReportQuery struct {
	port.QueryService
	rows map[string][][]any
}

var _ port.QueryService = fakeReportQuery{}

func (q fakeReportQuery) Query(_ context.Context, name string, _ ...any) (*model.QueryResult, error) {
	return &model.QueryResult{Rows: q.rows[name]}, nil
}
