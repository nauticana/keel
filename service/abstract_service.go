package service

import (
	"context"
	"errors"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

var errUninitialized = errors.New("service: AbstractService is not initialized; build it with NewAbstractService")

// AbstractService is the base a downstream service embeds by value to run its
// named-query catalog:
//
//	type FooService struct {
//	    service.AbstractService
//	}
//
//	func NewFooService(db port.DatabaseRepository) *FooService {
//	    return &FooService{AbstractService: service.NewAbstractService(db, fooQueries)}
//	}
type AbstractService struct {
	QS      port.QueryService
	db      port.DatabaseRepository
	queries map[string]string
}

// NewAbstractService prepares the catalog once; Query calls are lookups.
func NewAbstractService(db port.DatabaseRepository, queries map[string]string) AbstractService {
	return AbstractService{QS: db.GetQueryService(context.Background(), queries), db: db, queries: queries}
}

func (s *AbstractService) Query(ctx context.Context, name string, args ...any) (*model.QueryResult, error) {
	if s.QS == nil {
		return nil, errUninitialized
	}
	return s.QS.Query(ctx, name, args...)
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

func (s *AbstractService) QueryService() port.QueryService { return s.QS }

// Atomic runs fn over the service's catalog in one transaction, committed when
// fn returns nil and rolled back otherwise, even after the context is cancelled.
func (s *AbstractService) Atomic(ctx context.Context, fn func(tx port.TxQueryService) error) (err error) {
	if s.db == nil {
		return errUninitialized
	}
	tx, err := s.db.BeginTx(ctx, s.queries)
	if err != nil {
		return err
	}
	// A commit attempt ends the transaction either way, so only fn's failure rolls back.
	committing := false
	defer func() {
		if !committing {
			if rollbackErr := data.RollbackDetached(tx); rollbackErr != nil {
				err = errors.Join(err, rollbackErr)
			}
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	committing = true
	return tx.Commit(ctx)
}
