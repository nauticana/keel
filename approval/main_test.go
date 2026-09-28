package approval

import (
	"context"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/schema"
)

func TestMain(m *testing.M) {
	schema.LoadTestConfig()
	m.Run()
}

// memStore is an in-memory stand-in for the approval tables, driven by query name.
type memStore struct {
	requests map[int64][]any // selectRequestFields order
	events   [][]any
	single   map[int64]bool // approval_policy.allow_single_person by partner
	nextID   int64
	pending  []func() // undo log of the open transaction
}

func newStore() *memStore {
	return &memStore{requests: map[int64][]any{}, single: map[int64]bool{}}
}

func (m *memStore) GenID() int64                 { m.nextID++; return m.nextID }
func (m *memStore) Commit(context.Context) error { m.pending = nil; return nil }
func (m *memStore) Rollback(context.Context) error {
	for i := len(m.pending) - 1; i >= 0; i-- {
		m.pending[i]()
	}
	m.pending = nil
	return nil
}

func (m *memStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	out := &model.QueryResult{}
	switch name {
	case qInsertRequest:
		id := args[0].(int64)
		m.requests[id] = []any{id, args[1], args[2], args[3], StatusPending, args[4], time.Now(), nil, nil, nil}
		m.pending = append(m.pending, func() { delete(m.requests, id) })
	case qInsertEvent:
		n := len(m.events)
		m.events = append(m.events, []any{args[0], args[1], args[2], args[3], args[4], time.Now()})
		m.pending = append(m.pending, func() { m.events = m.events[:n] })
	case qGet, qLock:
		if r, ok := m.requests[args[1].(int64)]; ok && r[1] == args[0] {
			out.Rows = [][]any{r}
		}
	case qOpenFor:
		for _, r := range m.requests {
			if r[1] == args[0] && r[2] == args[1] && r[3] == args[2] && r[4] == StatusPending {
				out.Rows = [][]any{{r[0]}}
			}
		}
	case qLatestFor:
		var latest []any
		for _, r := range m.requests {
			if r[1] == args[0] && r[2] == args[1] && r[3] == args[2] && (latest == nil || r[0].(int64) > latest[0].(int64)) {
				latest = r
			}
		}
		if latest != nil {
			out.Rows = [][]any{latest}
		}
	case qPending:
		for id := int64(1); id <= m.nextID; id++ {
			if r, ok := m.requests[id]; ok && r[1] == args[0] && r[4] == StatusPending {
				out.Rows = append(out.Rows, r)
			}
		}
	case qAllowSingle:
		if v, ok := m.single[args[0].(int64)]; ok {
			out.Rows = [][]any{{v}}
		}
	case qSetDecision:
		r := m.requests[args[3].(int64)]
		prev := append([]any(nil), r...)
		r[4], r[7], r[8], r[9] = args[0], args[1], time.Now(), args[2]
		m.pending = append(m.pending, func() { copy(r, prev) })
	case qEvents:
		for _, e := range m.events {
			if e[1] == args[0] {
				out.Rows = append(out.Rows, e)
			}
		}
	}
	return out, nil
}

type memRepo struct {
	port.DatabaseRepository
	store *memStore
}

func (r memRepo) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r.store
}
func (r memRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return r.store, nil
}
