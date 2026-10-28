package data

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type cellRow []any

func (r cellRow) Scan(dest ...any) error {
	for i, d := range dest {
		switch p := d.(type) {
		case *int64:
			*p = r[i].(int64)
		case *string:
			*p = r[i].(string)
		}
	}
	return nil
}

type rowQS struct {
	rows []cellRow
	err  error
}

func (q *rowQS) Query(context.Context, string, ...any) (*model.QueryResult, error) { return nil, nil }
func (q *rowQS) GenID() int64                                                      { return 0 }
func (q *rowQS) QueryEach(_ context.Context, _ string, scan func(port.RowScanner) error, _ ...any) error {
	for _, r := range q.rows {
		if err := scan(r); err != nil {
			return err
		}
	}
	return q.err
}

type plainQS struct{ port.QueryService }

type widget struct {
	ID   int64
	Name string
}

func scanWidget(r port.RowScanner) (widget, error) {
	var w widget
	return w, r.Scan(&w.ID, &w.Name)
}

func TestCollect(t *testing.T) {
	qs := &rowQS{rows: []cellRow{{int64(1), "a"}, {int64(2), "b"}}}
	got, err := Collect(context.Background(), qs, "q", scanWidget)
	if err != nil || !slices.Equal(got, []widget{{1, "a"}, {2, "b"}}) {
		t.Fatalf("Collect = %v, %v", got, err)
	}

	boom := errors.New("boom")
	if got, err := Collect(context.Background(), qs, "q", func(port.RowScanner) (widget, error) { return widget{}, boom }); !errors.Is(err, boom) || got != nil {
		t.Errorf("scan error: %v, %v", got, err)
	}
	if _, err := Collect(context.Background(), &rowQS{err: boom}, "q", scanWidget); !errors.Is(err, boom) {
		t.Errorf("query error: %v", err)
	}
	if _, err := Collect(context.Background(), plainQS{}, "q", scanWidget); !errors.Is(err, ErrRowsUnsupported) {
		t.Errorf("plain service: %v", err)
	}
}
