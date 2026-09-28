package erasure

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/schema"
)

func TestMain(m *testing.M) {
	schema.LoadTestConfig()
	m.Run()
}

type auditKey struct {
	request    int64
	table, key string
}

type holdRow struct {
	userID, placedBy int
	reason           string
	released         bool
}

// memStore is an in-memory stand-in for the erasure and legal-hold tables,
// driven by query name. It is both the plain and the transactional query
// service; audit and pseudonym writes of a rolled-back transaction vanish.
type memStore struct {
	users      map[int]bool
	holds      map[int64]*holdRow
	requests   map[int64][]any // selectRequestField order
	leases     map[int64]int64 // request id → lease token
	audit      map[auditKey][]any
	pseudonyms map[int]string
	lookups    [][]any // user, actor, reason
	catalogs   []string
	nextID     int64
	commits    int
	rollbacks  int

	inTx          bool
	txAudit       []auditKey
	txPseudonyms  []int
	failQuery     map[string]error
	onActiveHold  func(userID int) // runs before each hold check
	auditSequence []auditKey
}

func newMemStore(userIDs ...int) *memStore {
	m := &memStore{
		users: map[int]bool{}, holds: map[int64]*holdRow{}, requests: map[int64][]any{}, leases: map[int64]int64{},
		audit: map[auditKey][]any{}, pseudonyms: map[int]string{}, failQuery: map[string]error{},
	}
	for _, id := range userIDs {
		m.users[id] = true
	}
	return m
}

func (m *memStore) GenID() int64 { m.nextID++; return m.nextID }

func (m *memStore) Commit(context.Context) error {
	m.commits++
	m.inTx, m.txAudit, m.txPseudonyms = false, nil, nil
	return nil
}

func (m *memStore) Rollback(context.Context) error {
	m.rollbacks++
	for _, k := range m.txAudit {
		delete(m.audit, k)
		m.auditSequence = slices.DeleteFunc(m.auditSequence, func(x auditKey) bool { return x == k })
	}
	for _, u := range m.txPseudonyms {
		delete(m.pseudonyms, u)
	}
	m.inTx, m.txAudit, m.txPseudonyms = false, nil, nil
	return nil
}

func (m *memStore) QueryService(catalogID string, _ map[string]string) port.QueryService {
	m.catalogs = append(m.catalogs, catalogID)
	return m
}

func (m *memStore) held(userID int) bool {
	for _, h := range m.holds {
		if h.userID == userID && !h.released {
			return true
		}
	}
	return false
}

// leased runs fn on the request row when the lease token matches.
func (m *memStore) leased(id, token int64, fn func(row []any)) *model.QueryResult {
	if m.leases[id] != token {
		return &model.QueryResult{}
	}
	fn(m.requests[id])
	delete(m.leases, id)
	return &model.QueryResult{Rows: [][]any{{id}}}
}

func (m *memStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	if err := m.failQuery[name]; err != nil {
		return nil, err
	}
	out := &model.QueryResult{}
	switch name {
	case qLockUser:
		if m.users[args[0].(int)] {
			out.Rows = [][]any{{int64(args[0].(int))}}
		}
	case qActiveHold:
		if m.onActiveHold != nil {
			m.onActiveHold(args[0].(int))
		}
		if m.held(args[0].(int)) {
			out.Rows = [][]any{{1}}
		}
	case qOpenRequest:
		var best []any
		for _, r := range m.requests {
			if r[1] == int64(args[0].(int)) && slices.Contains([]any{StatusPending, StatusActive, StatusHeld}, r[2]) &&
				(best == nil || r[0].(int64) > best[0].(int64)) {
				best = r
			}
		}
		if best != nil {
			out.Rows = [][]any{best}
		}
	case qInsertRequest:
		id := args[0].(int64)
		m.requests[id] = []any{id, int64(args[1].(int)), args[2], int64(args[3].(int)), time.Now(), int64(0), nil, nil}
	case qGetRequest:
		if r, ok := m.requests[args[0].(int64)]; ok {
			out.Rows = [][]any{r}
		}
	case qCancelRequest:
		if r, ok := m.requests[args[0].(int64)]; ok && (r[2] == StatusPending || r[2] == StatusHeld) {
			r[2], r[6] = StatusCancelled, time.Now()
			out.Rows = [][]any{{r[0]}}
		}
	case qInsertAudit:
		k := auditKey{args[0].(int64), args[1].(string), args[2].(string)}
		if _, dup := m.audit[k]; dup {
			break
		}
		m.audit[k] = []any{k.table, k.key, args[3], args[4], time.Now()}
		m.auditSequence = append(m.auditSequence, k)
		if m.inTx {
			m.txAudit = append(m.txAudit, k)
		}
		out.Rows = [][]any{{k.request}}
	case qListAudit:
		for _, k := range m.auditSequence {
			if k.request == args[0].(int64) {
				out.Rows = append(out.Rows, m.audit[k])
			}
		}
	case qPlaceHold:
		m.holds[args[0].(int64)] = &holdRow{userID: args[1].(int), reason: args[2].(string), placedBy: args[3].(int)}
	case qReleaseHold:
		if h, ok := m.holds[args[1].(int64)]; ok && !h.released {
			h.released = true
			out.Rows = [][]any{{args[1]}}
		}
	case qListHolds:
		for id, h := range m.holds {
			if h.userID == args[0].(int) && !h.released {
				out.Rows = append(out.Rows, []any{id, int64(h.userID), h.reason, int64(h.placedBy), time.Now()})
			}
		}
	case qEnsurePseudonym:
		if _, ok := m.pseudonyms[args[0].(int)]; !ok {
			m.pseudonyms[args[0].(int)] = args[1].(string)
			if m.inTx {
				m.txPseudonyms = append(m.txPseudonyms, args[0].(int))
			}
		}
	case qGetPseudonym:
		if p, ok := m.pseudonyms[args[0].(int)]; ok {
			out.Rows = [][]any{{p}}
		}
	case qResolvePseudonym:
		for u, p := range m.pseudonyms {
			if p == args[0] {
				out.Rows = [][]any{{int64(u)}}
			}
		}
	case qInsertLookup:
		m.lookups = append(m.lookups, []any{args[1], args[2], args[3]})
	case qDropPseudonym:
		delete(m.pseudonyms, args[0].(int))
	case qWorkerDone:
		out = m.leased(args[0].(int64), args[1].(int64), func(r []any) { r[2], r[6], r[7] = StatusDone, time.Now(), nil })
	case qWorkerHeld:
		out = m.leased(args[0].(int64), args[1].(int64), func(r []any) { r[2] = StatusHeld })
	case qWorkerRetry:
		out = m.leased(args[2].(int64), args[3].(int64), func(r []any) { r[2], r[5], r[7] = StatusPending, r[5].(int64)+1, args[0] })
	case qWorkerFail:
		out = m.leased(args[1].(int64), args[2].(int64), func(r []any) { r[2], r[5], r[7] = StatusFailed, r[5].(int64)+1, args[0] })
	default:
		return nil, errors.New("unexpected query " + name)
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
	r.store.inTx = true
	return r.store, nil
}

// memClassifier classifies a fixed set of rows and records what it erased.
type memClassifier struct {
	table   string
	items   []Item
	erased  []string // action:key:pseudonym
	failKey string
	onErase func(Item)
}

func (c *memClassifier) Table() string              { return c.table }
func (c *memClassifier) Queries() map[string]string { return map[string]string{} }
func (c *memClassifier) Classify(context.Context, port.QueryService, int) ([]Item, error) {
	return slices.Clone(c.items), nil
}
func (c *memClassifier) Erase(_ context.Context, tx port.QueryService, _ int, item Item, pseudonym string) error {
	if tx == nil {
		return errors.New("no transaction")
	}
	if c.onErase != nil {
		c.onErase(item)
	}
	if item.Key == c.failKey {
		return errors.New("row locked")
	}
	c.erased = append(c.erased, string(item.Action)+":"+item.Key+":"+pseudonym)
	return nil
}

type memAccounts struct {
	deleted []int
	err     error
}

func (a *memAccounts) DeleteAccount(userID int, _ string) error {
	if a.err != nil {
		return a.err
	}
	a.deleted = append(a.deleted, userID)
	return nil
}

type memJournal struct {
	logger.ApplicationLogger
	lines []string
}

func (j *memJournal) Info(s string)    { j.lines = append(j.lines, "I "+s) }
func (j *memJournal) Warning(s string) { j.lines = append(j.lines, "W "+s) }
func (j *memJournal) Error(s string)   { j.lines = append(j.lines, "E "+s) }

func newTestService(store *memStore, accounts *memAccounts, classifiers ...Classifier) *Service {
	return &Service{DB: memRepo{store: store}, Accounts: accounts, Classifiers: classifiers}
}

func activityClassifier() *memClassifier {
	return &memClassifier{table: "activity", items: []Item{
		{Key: "1", Action: ActionDelete},
		{Key: "2", Action: ActionAnonymize},
		{Key: "3", Action: ActionHold, Reason: "incident 17"},
	}}
}
