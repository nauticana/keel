package service

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/keeltest"
	"github.com/nauticana/keel/port"
)

func TestAtomicCommitsAndRollsBack(t *testing.T) {
	db := keeltest.NewDatabase()
	svc := NewAbstractService(db, map[string]string{"write": "UPDATE t SET a = ?"})
	if err := svc.Atomic(context.Background(), func(tx port.TxQueryService) error {
		_, err := tx.Query(context.Background(), "write", 1)
		return err
	}); err != nil || !db.Tx.Committed || db.Tx.RolledBack || len(db.Tx.Calls["write"]) != 1 {
		t.Fatalf("commit: err %v, tx %+v", err, db.Tx)
	}

	db = keeltest.NewDatabase()
	svc = NewAbstractService(db, nil)
	boom := errors.New("boom")
	if err := svc.Atomic(context.Background(), func(port.TxQueryService) error { return boom }); !errors.Is(err, boom) || db.Tx.Committed || !db.Tx.RolledBack {
		t.Fatalf("rollback: err %v, tx %+v", err, db.Tx)
	}
}

func TestAtomicReportsRollbackAndCommitFailures(t *testing.T) {
	boom, stuck := errors.New("boom"), errors.New("stuck")
	db := keeltest.NewDatabase()
	db.Tx.RollbackErr = stuck
	svc := NewAbstractService(db, nil)
	if err := svc.Atomic(context.Background(), func(port.TxQueryService) error { return boom }); !errors.Is(err, boom) || !errors.Is(err, stuck) {
		t.Fatalf("failed rollback: %v, want both errors", err)
	}
	db.Tx.CommitErr = boom
	if err := svc.Atomic(context.Background(), func(port.TxQueryService) error { return nil }); !errors.Is(err, boom) || errors.Is(err, stuck) {
		t.Fatalf("failed commit: %v, want the commit error without a rollback", err)
	}
}

func TestAtomicZeroValueFails(t *testing.T) {
	var svc AbstractService
	if _, err := svc.QueryFirst(context.Background(), "q"); err == nil {
		t.Fatal("zero AbstractService ran a query")
	}
	if err := svc.Exec(context.Background(), "q"); err == nil {
		t.Fatal("zero AbstractService ran a statement")
	}
	if err := svc.Atomic(context.Background(), func(port.TxQueryService) error { return nil }); err == nil {
		t.Fatal("zero AbstractService ran a transaction")
	}
}
