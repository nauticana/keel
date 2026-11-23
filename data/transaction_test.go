package data

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/port"
)

type countingTx struct {
	port.TxQueryService
	commits, rollbacks int
	commitErr          error
}

func (t *countingTx) Commit(context.Context) error   { t.commits++; return t.commitErr }
func (t *countingTx) Rollback(context.Context) error { t.rollbacks++; return nil }

type txRepo struct {
	port.DatabaseRepository
	tx  *countingTx
	err error
}

func (r txRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return r.tx, r.err
}

func TestInTx(t *testing.T) {
	failed := errors.New("failed")
	cases := []struct {
		name               string
		repo               txRepo
		fnErr              error
		want               error
		commits, rollbacks int
	}{
		{"commit", txRepo{tx: &countingTx{}}, nil, nil, 1, 0},
		{"fn error", txRepo{tx: &countingTx{}}, failed, failed, 0, 1},
		{"commit error", txRepo{tx: &countingTx{commitErr: failed}}, nil, failed, 1, 1},
		{"begin error", txRepo{tx: &countingTx{}, err: failed}, nil, failed, 0, 0},
	}
	for _, c := range cases {
		err := InTx(context.Background(), c.repo, nil, func(port.TxQueryService) error { return c.fnErr })
		if !errors.Is(err, c.want) || c.repo.tx.commits != c.commits || c.repo.tx.rollbacks != c.rollbacks {
			t.Errorf("%s: err %v, commits %d, rollbacks %d", c.name, err, c.repo.tx.commits, c.repo.tx.rollbacks)
		}
	}
}
