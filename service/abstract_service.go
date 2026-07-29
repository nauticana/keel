package service

import (
	"context"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// AbstractService is the OO base for downstream projects that talk to the database through QueryService
// interface. Concrete services embed it by value at the top of the struct declaration:
//
//	type FooServiceImpl struct {
//	    AbstractService
//	    other deps...
//	}
//
//	func NewFooService(db port.DatabaseRepository) port.FooService {
//	    return &FooServiceImpl{
//	        AbstractService: NewAbstractService(db, fooQueries),
//	    }
//	}
//
// Method promotion gives subclasses `Query`, `QueryRows`, `QueryFirst`, and `Exec` for free.
type AbstractService struct {
	qs port.QueryService
}

// NewAbstractService caches a QueryService bound to the given query map. The
// map is rewritten once per backend (?→$N for Postgres) at construction time;
// subsequent Query calls are zero-allocation lookups.
func NewAbstractService(db port.DatabaseRepository, queries map[string]string) AbstractService {
	return AbstractService{qs: db.GetQueryService(context.Background(), queries)}
}

// Query is the raw passthrough to keel's QueryService. Prefer the typed
// helpers below; reach for Query only when you need access to Columns or
// when neither QueryFirst nor QueryRows fits.
func (s *AbstractService) Query(ctx context.Context, name string, args ...any) (*model.QueryResult, error) {
	return s.qs.Query(ctx, name, args...)
}

// QueryRows runs the named query and returns every row. Wraps the
// `(*model.QueryResult, error) → ([][]any, error)` conversion every Impl
// was repeating.
func (s *AbstractService) QueryRows(ctx context.Context, name string, args ...any) ([][]any, error) {
	res, err := s.qs.Query(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// QueryFirst returns the first row, or nil if the result set is empty.
// Idiomatic for `SELECT ... LIMIT 1` / `RETURNING id` queries.
func (s *AbstractService) QueryFirst(ctx context.Context, name string, args ...any) ([]any, error) {
	res, err := s.qs.Query(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, nil
	}
	return res.Rows[0], nil
}

// Exec runs the named query and discards the result rows. Idiomatic for
// INSERT / UPDATE / DELETE where only the error matters.
func (s *AbstractService) Exec(ctx context.Context, name string, args ...any) error {
	_, err := s.qs.Query(ctx, name, args...)
	return err
}

// QueryService returns the underlying QueryService for callers that need
// transactional / streaming patterns the helpers above don't cover.
func (s *AbstractService) QueryService() port.QueryService { return s.qs }
