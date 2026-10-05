package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/schema"
)

func TestMain(m *testing.M) {
	schema.LoadTestConfig()
	m.Run()
}

// memStore is an in-memory stand-in for the account tables, driven by query name.
// Queries it does not model are recorded in calls and return no rows.
type memStore struct {
	users     map[int]bool      // existing user_account ids
	cutoffs   map[int]time.Time // tokens_valid_after
	holds     map[int]bool      // users with an unreleased legal hold
	deleted   map[int]bool
	partners  map[int][][]any // qListPartners rows per user
	accounts  map[int]*account
	links     map[string]int // issuer|subject → user id
	calls     []string
	failQuery map[string]error
	commits   int
	rollbacks int
	nextID    int64
}

func newMemStore(userIDs ...int) *memStore {
	m := &memStore{users: map[int]bool{}, cutoffs: map[int]time.Time{}, holds: map[int]bool{}, deleted: map[int]bool{}, failQuery: map[string]error{},
		accounts: map[int]*account{}, links: map[string]int{}}
	for _, id := range userIDs {
		m.users[id] = true
	}
	return m
}

// account is a user_account row for the identity-linking queries.
type account struct {
	email, status string
}

func (m *memStore) addAccount(id int, email, status string) {
	m.users[id] = true
	m.accounts[id] = &account{email: email, status: status}
}

func (m *memStore) userByEmail(email string) int {
	for id, a := range m.accounts {
		if a.email != "" && a.email == email {
			return id
		}
	}
	return 0
}

func (m *memStore) GenID() int64                   { m.nextID++; return m.nextID }
func (m *memStore) Commit(context.Context) error   { m.commits++; return nil }
func (m *memStore) Rollback(context.Context) error { m.rollbacks++; return nil }

func (m *memStore) count(name string) int {
	n := 0
	for _, c := range m.calls {
		if c == name {
			n++
		}
	}
	return n
}

func (m *memStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	m.calls = append(m.calls, name)
	if err := m.failQuery[name]; err != nil {
		return nil, err
	}
	out := &model.QueryResult{}
	switch name {
	case qTokensValidAfter:
		if at, ok := m.cutoffs[args[0].(int)]; ok {
			out.Rows = [][]any{{at}}
		} else if m.users[args[0].(int)] {
			out.Rows = [][]any{{nil}}
		}
	case qRevokeAccessTokens:
		if m.users[args[0].(int)] {
			at := time.Now()
			m.cutoffs[args[0].(int)] = at
			out.Rows = [][]any{{at}}
		}
	case qLockUserAccount:
		if m.users[args[0].(int)] {
			out.Rows = [][]any{{int64(args[0].(int))}}
		}
	case qActiveLegalHold:
		if m.holds[args[0].(int)] {
			out.Rows = [][]any{{1}}
		}
	case qListPartners:
		out.Rows = m.partners[args[0].(int)]
	case qUserByExternalIdentity:
		if id, ok := m.links[fmt.Sprint(args[0], "|", args[1])]; ok {
			a := m.accounts[id]
			out.Rows = [][]any{{int64(id), "F", "L", a.email, nil, nil, a.status, int64(0), nil}}
		}
	case qUserIDByEmail:
		if id := m.userByEmail(args[0].(string)); id != 0 {
			out.Rows = [][]any{{int64(id)}}
		}
	case qPartnerUserByEmail:
		if id := m.userByEmail(args[0].(string)); id != 0 {
			a := m.accounts[id]
			out.Rows = [][]any{{int64(id), "F", "L", a.email, a.status, nil, nil, int16(0), nil, nil, int64(0), nil}}
		}
	case qLinkExternalIdentity:
		k := fmt.Sprint(args[2], "|", args[3])
		for lk, uid := range m.links {
			if lk == k || (uid == args[0].(int) && strings.HasPrefix(lk, fmt.Sprint(args[2], "|"))) {
				return nil, &pgconn.PgError{Code: "23505"}
			}
		}
		m.links[k] = args[0].(int)
	case qCreateSocialUser:
		email, _ := args[3].(string)
		if email != "" && m.userByEmail(email) != 0 {
			return nil, &pgconn.PgError{Code: "23505", ConstraintName: "user_account_email_uq"}
		}
		m.addAccount(int(args[0].(int64)), email, UserStatusActive)
	case qAnonymizeUserAccount:
		m.deleted[args[2].(int)] = true
		m.cutoffs[args[2].(int)] = time.Now()
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

func newLocalUserService(t *testing.T, store *memStore) *LocalUserService {
	t.Helper()
	s, err := NewLocalUserService(context.Background(), memRepo{store: store}, "test-secret", "test")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var errDatabaseDown = errors.New("database down")
