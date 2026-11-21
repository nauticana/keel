package handler

import (
	"context"
	"errors"
	"strings"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// catalogDB answers the geo.Catalog queries by table, or fails every one.
type catalogDB struct {
	port.DatabaseRepository
	fail bool
}

func (d *catalogDB) GetQueryService(context.Context, map[string]string) port.QueryService { return d }
func (d *catalogDB) GenID() int64                                                         { return 0 }
func (d *catalogDB) Query(_ context.Context, name string, _ ...any) (*model.QueryResult, error) {
	if d.fail {
		return nil, errors.New("pq: relation country is broken")
	}
	switch {
	case strings.HasSuffix(name, "countries"):
		return &model.QueryResult{Rows: [][]any{{"TR", "Turkey"}, {"US", "United States"}}}, nil
	case strings.HasSuffix(name, "states"):
		return &model.QueryResult{Rows: [][]any{{"US", "AL", "Alabama"}}}, nil
	default:
		return &model.QueryResult{Rows: [][]any{{"USD", "US Dollar", int64(2)}}}, nil
	}
}
