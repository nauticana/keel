package guard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
)

type lockTx struct {
	calls []string
	args  []any
	rows  map[string][][]any
	err   error
}

func (t *lockTx) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	t.calls = append(t.calls, name)
	t.args = append(t.args, args...)
	if name == QueryLock && t.err != nil {
		return nil, t.err
	}
	return &model.QueryResult{Rows: t.rows[name]}, nil
}
func (t *lockTx) GenID() int64                   { return 1 }
func (t *lockTx) Commit(context.Context) error   { return nil }
func (t *lockTx) Rollback(context.Context) error { return nil }

func TestLockThenCheckInOneTransaction(t *testing.T) {
	tx := &lockTx{rows: map[string][][]any{"dup": {{int64(42)}}}}
	if err := Lock(context.Background(), tx, "7:scan"); err != nil {
		t.Fatal(err)
	}
	err := NewDuplicateGuard("dup", time.Hour).Check(context.Background(), tx, GuardInput{PartnerID: 7, DedupKey: "scan", Now: time.Now()})
	var dup *DuplicateError
	if !errors.As(err, &dup) || dup.ExistingID != 42 {
		t.Fatalf("err = %v, want duplicate of 42", err)
	}
	if len(tx.calls) != 2 || tx.calls[0] != QueryLock || tx.args[0] != "guard:7:scan" {
		t.Fatalf("calls = %v args = %v, want the namespaced lock first", tx.calls, tx.args)
	}
	if Queries[QueryLock] == "" {
		t.Fatal("QueryLock missing from Queries")
	}
}

func TestLockFailures(t *testing.T) {
	tx := &lockTx{}
	if err := Lock(context.Background(), tx, " "); !errors.Is(err, ErrNoLockKey) || len(tx.calls) != 0 {
		t.Fatalf("blank key: %v, calls %v", err, tx.calls)
	}
	tx.err = errors.New("deadlock detected")
	if err := Lock(context.Background(), tx, "k"); !errors.Is(err, tx.err) {
		t.Fatalf("lock error not surfaced: %v", err)
	}
}
