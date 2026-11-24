package service

import (
	"context"
	"errors"
	"sync"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

var errUninitialized = errors.New("service: AbstractService has no DB")

// AbstractService is the base a downstream service embeds to run its
// named-query catalog, prepared on first use:
//
//	type FooService struct {
//	    service.AbstractService
//	}
//
//	func NewFooService(db port.DatabaseRepository) *FooService {
//	    return &FooService{AbstractService: service.AbstractService{DB: db, Queries: fooQueries}}
//	}
type AbstractService struct {
	DB      port.DatabaseRepository
	Queries map[string]string

	once sync.Once
	qs   port.QueryService
}

func (s *AbstractService) Query(ctx context.Context, name string, args ...any) (*model.QueryResult, error) {
	if s.DB == nil {
		return nil, errUninitialized
	}
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, s.Queries) })
	return s.qs.Query(ctx, name, args...)
}

// QueryRows runs the named query and returns every row.
func (s *AbstractService) QueryRows(ctx context.Context, name string, args ...any) ([][]any, error) {
	res, err := s.Query(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// QueryFirst returns the first row, or nil when there is none.
func (s *AbstractService) QueryFirst(ctx context.Context, name string, args ...any) ([]any, error) {
	rows, err := s.QueryRows(ctx, name, args...)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// Exec runs the named query and discards its rows.
func (s *AbstractService) Exec(ctx context.Context, name string, args ...any) error {
	_, err := s.Query(ctx, name, args...)
	return err
}

// Atomic runs fn over the service's catalog in one transaction, committed when
// fn returns nil and rolled back otherwise, even after the context is cancelled.
func (s *AbstractService) Atomic(ctx context.Context, fn func(tx port.TxQueryService) error) error {
	if s.DB == nil {
		return errUninitialized
	}
	return data.InTx(ctx, s.DB, s.Queries, fn)
}
