package user

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type memberQueries struct {
	port.QueryService
	args []any
}

func (q *memberQueries) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	if name != qMembers {
		return nil, errors.New("unexpected query " + name)
	}
	q.args = args
	return &model.QueryResult{Rows: [][]any{{int64(4), "Ada Lovelace"}}}, nil
}

func TestMembers(t *testing.T) {
	s := newLocalUserService(t, newMemStore())
	q := &memberQueries{}
	s.queryService = q
	got, err := s.Members(7, "  A%d_! ")
	if err != nil || len(got) != 1 || got[0] != (Member{UserID: 4, Name: "Ada Lovelace"}) {
		t.Fatalf("Members = %v, %v", got, err)
	}
	if q.args[0] != int64(7) || q.args[1] != "%a!%d!_!!%" || q.args[2].(int) <= 0 {
		t.Fatalf("args = %v", q.args)
	}
	if _, err := s.Members(7, strings.Repeat("x", MaxMemberSearch+1)); err == nil {
		t.Fatal("over-long search accepted")
	}
	if _, err := s.Members(0, ""); !errors.Is(err, ErrNoMembership) {
		t.Fatalf("no partner: %v", err)
	}
	sql := LocalUserQueries[qMembers]
	for _, want := range []string{"p.endda IS NULL OR p.endda > CURRENT_TIMESTAMP", "u.status <> 'D'", "LIMIT ?"} {
		if !strings.Contains(sql, want) {
			t.Errorf("members query lacks %q", want)
		}
	}
}
