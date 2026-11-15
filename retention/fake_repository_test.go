package retention

import (
	"context"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// fakeRepository holds rows of one table as their age-column times.
type fakeRepository struct {
	port.DatabaseRepository
	tables  map[string]*model.TableDefinition
	rows    map[string][]time.Time
	fail    map[string]error
	queries map[string]string
	calls   int
}

func (f *fakeRepository) GetTableDefinition(name string) *model.TableDefinition {
	return f.tables[name]
}

func (f *fakeRepository) GetQueryService(_ context.Context, queries map[string]string) port.QueryService {
	f.queries = queries
	return f
}

func (f *fakeRepository) GenID() int64 { return 0 }

func (f *fakeRepository) Query(_ context.Context, table string, args ...any) (*model.QueryResult, error) {
	f.calls++
	if err := f.fail[table]; err != nil {
		return nil, err
	}
	cutoff, limit := args[0].(time.Time), args[1].(int)
	res, kept := &model.QueryResult{}, f.rows[table][:0]
	for _, at := range f.rows[table] {
		if at.Before(cutoff) && len(res.Rows) < limit {
			res.Rows = append(res.Rows, []any{1})
			continue
		}
		kept = append(kept, at)
	}
	f.rows[table] = kept
	return res, nil
}
