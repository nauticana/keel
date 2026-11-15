package keeltest

import (
	"context"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// Queries is a scripted QueryService and transaction: each named query returns
// its scripted error, answer or rows, else no rows, and every call is recorded.
type Queries struct {
	Results               map[string]*model.QueryResult
	Answers               map[string]func(args []any) [][]any
	Errs                  map[string]error
	Calls                 map[string][][]any
	Committed, RolledBack bool
	// CommitErr and RollbackErr fail the transaction's end.
	CommitErr, RollbackErr error
	id                     int64
}

func NewQueries() *Queries {
	return &Queries{Results: map[string]*model.QueryResult{}, Answers: map[string]func([]any) [][]any{},
		Errs: map[string]error{}, Calls: map[string][][]any{}}
}

// Rows scripts the rows of a named query.
func (q *Queries) Rows(name string, rows ...[]any) *Queries {
	q.Results[name] = &model.QueryResult{Rows: rows}
	return q
}

// Answer scripts a named query whose rows depend on its arguments.
func (q *Queries) Answer(name string, rows func(args []any) [][]any) *Queries {
	q.Answers[name] = rows
	return q
}

// Fail scripts the error of a named query.
func (q *Queries) Fail(name string, err error) *Queries {
	q.Errs[name] = err
	return q
}

func (q *Queries) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	q.Calls[name] = append(q.Calls[name], args)
	if err, ok := q.Errs[name]; ok {
		return nil, err
	}
	if answer, ok := q.Answers[name]; ok {
		return &model.QueryResult{Rows: answer(args)}, nil
	}
	if res, ok := q.Results[name]; ok {
		return res, nil
	}
	return &model.QueryResult{}, nil
}

// GenID returns 1, 2, 3, …
func (q *Queries) GenID() int64 { q.id++; return q.id }

func (q *Queries) Commit(context.Context) error {
	q.Committed = q.CommitErr == nil
	return q.CommitErr
}

func (q *Queries) Rollback(context.Context) error {
	q.RolledBack = q.RollbackErr == nil
	return q.RollbackErr
}

var _ port.TxQueryService = (*Queries)(nil)
