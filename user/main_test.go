package user

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
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
	users      map[int]bool      // existing user_account ids
	cutoffs    map[int]time.Time // tokens_valid_after
	holds      map[int]bool      // users with an unreleased legal hold
	deleted    map[int]bool
	partners   map[int][][]any // qListPartners rows per user
	accounts   map[int]*account
	links      map[string]int    // issuer|subject → user id
	grants     map[string]string // issuer|subject → provider_grant
	members    map[[2]int64]bool // {user, partner} with an open membership
	tokens     map[string]*refreshRow
	loginRow   []any                    // qUserByLogin row
	endedRoles []int                    // users whose open role assignments were ended
	policies   map[int64]map[string]int // user_account_policy by partner; 0 = global
	networks   map[int64][]string       // partner_signin_network
	clock      time.Duration            // offset added to the wall clock
	calls      []string
	failQuery  map[string]error
	commits    int
	rollbacks  int
	nextID     int64
}

func newMemStore(userIDs ...int) *memStore {
	m := &memStore{users: map[int]bool{}, cutoffs: map[int]time.Time{}, holds: map[int]bool{}, deleted: map[int]bool{}, failQuery: map[string]error{},
		accounts: map[int]*account{}, links: map[string]int{}, grants: map[string]string{}, members: map[[2]int64]bool{}, tokens: map[string]*refreshRow{}, policies: map[int64]map[string]int{}, networks: map[int64][]string{}}
	for _, id := range userIDs {
		m.users[id] = true
	}
	return m
}

type refreshRow struct {
	user    int
	revoked bool
	started time.Time
	created time.Time
	method  string
	maxAge  any
	session int64
	agent   any
	ip      any
	device  any
}

// now is the store clock; tests move it with clock.
func (m *memStore) now() time.Time { return time.Now().Add(m.clock) }

// account is a user_account row for the identity-linking queries.
type account struct {
	email, status string
	verifiedBy    string // email_verification_method; "" = never verified
}

// addAccount adds an account whose email was verified at registration.
func (m *memStore) addAccount(id int, email, status string) {
	m.users[id] = true
	m.accounts[id] = &account{email: email, status: status, verifiedBy: EmailVerifiedByRegistration}
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
func (m *memStore) QueryService(string, map[string]string) port.QueryService {
	return m
}

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
	case qInsertRefreshToken:
		row := &refreshRow{user: args[0].(int), started: m.now(), created: m.now(), session: args[6].(int64), agent: args[7], ip: args[8], device: args[9]}
		if started, ok := args[3].(time.Time); ok {
			row.started = started
		}
		row.method, _ = args[4].(string)
		row.maxAge = args[5]
		m.tokens[args[1].(string)] = row
	case qDeviceSeen:
		prior, known := false, false
		for _, t := range m.tokens {
			if t.user == args[0].(int) {
				prior = true
				known = known || t.device == args[2]
			}
		}
		out.Rows = [][]any{{prior, known}}
	case qLiveSessions:
		for _, t := range m.tokens {
			if t.user == args[0].(int) && !t.revoked {
				var method any
				if t.method != "" {
					method = t.method
				}
				out.Rows = append(out.Rows, []any{t.session, t.agent, t.ip, method, t.started, t.created})
			}
		}
	case qRevokeSession:
		for _, t := range m.tokens {
			if t.user == args[0].(int) && t.session == args[1].(int64) && !t.revoked {
				t.revoked = true
				out.Rows = append(out.Rows, []any{t.session})
			}
		}
	case qRevokeSessionsOverCap:
		var live []*refreshRow
		for _, t := range m.tokens {
			if t.user == args[0].(int) && !t.revoked {
				live = append(live, t)
			}
		}
		slices.SortFunc(live, func(a, b *refreshRow) int { return cmp.Compare(b.session, a.session) })
		for i, t := range live {
			if i >= args[2].(int) {
				t.revoked = true
			}
		}
	case qSignInNetworks:
		var partner int64
		for k := range m.members {
			if k[0] == int64(args[0].(int)) {
				partner = k[1]
			}
		}
		for _, c := range m.networks[partner] {
			out.Rows = append(out.Rows, []any{c})
		}
	case qRevokeRefreshToken:
		if t := m.tokens[args[0].(string)]; t != nil {
			t.revoked = true
		}
	case qRevokeAllRefreshTokensForID:
		for _, t := range m.tokens {
			if t.user == args[0].(int) {
				t.revoked = true
			}
		}
	case qGetRefreshToken:
		if t := m.tokens[args[0].(string)]; t != nil && !t.revoked {
			var partner any
			for k := range m.members {
				if k[0] == int64(t.user) {
					partner = k[1]
				}
			}
			status := UserStatusActive
			if a := m.accounts[t.user]; a != nil {
				status = a.status
			}
			var method any
			if t.method != "" {
				method = t.method
			}
			age := int64(m.now().Sub(t.started) / time.Second)
			out.Rows = [][]any{{int64(t.user), "F", "L", "", status, false, partner, nil, nil, t.started, method, age, t.maxAge, t.session, t.device}}
		}
	case qEndMembership:
		k := [2]int64{int64(args[0].(int)), args[1].(int64)}
		if m.members[k] {
			delete(m.members, k)
			out.Rows = [][]any{{args[1]}}
		}
	case qUserByLogin, qUserByLoginEmail:
		if m.loginRow != nil {
			out.Rows = [][]any{m.loginRow}
		}
	case qEffectivePolicies, qUserPolicies:
		// The partner's row overrides the global one, per policy type.
		partner, _ := args[0].(int64)
		if name == qUserPolicies {
			for k := range m.members {
				if k[0] == int64(args[0].(int)) {
					partner = k[1]
				}
			}
		}
		effective := map[string]int{}
		for policy, value := range m.policies[0] {
			effective[policy] = value
		}
		for policy, value := range m.policies[partner] {
			effective[policy] = value
		}
		for policy, value := range effective {
			out.Rows = append(out.Rows, []any{policy, int32(value)})
		}
	case qEndPermissions:
		m.endedRoles = append(m.endedRoles, args[0].(int))
	case qUserById:
		if m.users[args[0].(int)] {
			out.Rows = [][]any{{int64(args[0].(int)), "u", "F", "L", "", UserStatusActive, nil, nil, int16(0), nil, int64(0), nil, false}}
		}
	case qUserByExternalIdentity:
		if id, ok := m.links[fmt.Sprint(args[0], "|", args[1])]; ok {
			a := m.accounts[id]
			out.Rows = [][]any{{int64(id), "F", "L", a.email, nil, nil, a.status, int64(0), nil}}
		}
	case qUserIDByEmail:
		if id := m.userByEmail(args[0].(string)); id != 0 {
			var verifiedAt any
			if m.accounts[id].verifiedBy != "" {
				verifiedAt = time.Now()
			}
			out.Rows = [][]any{{int64(id), verifiedAt}}
		}
	case qMarkEmailVerified:
		if a := m.accounts[args[1].(int)]; a != nil && a.email != "" {
			a.verifiedBy = args[0].(string)
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
		if g, ok := args[4].(string); ok {
			m.grants[k] = g
		}
	case qStoreIdentityGrant:
		m.grants[fmt.Sprint(args[1], "|", args[2])] = args[0].(string)
	case qIdentityGrantsForUser:
		for k, uid := range m.links {
			if g := m.grants[k]; uid == args[0].(int) && g != "" {
				out.Rows = append(out.Rows, []any{strings.SplitN(k, "|", 2)[0], g})
			}
		}
	case qDeleteExternalIdentities:
		for k, uid := range m.links {
			if uid == args[0].(int) {
				delete(m.links, k)
				delete(m.grants, k)
			}
		}
	case qCreateSocialUser:
		email, _ := args[3].(string)
		if email != "" && m.userByEmail(email) != 0 {
			return nil, &pgconn.PgError{Code: "23505", ConstraintName: "user_account_email_uq"}
		}
		m.users[int(args[0].(int64))] = true
		m.accounts[int(args[0].(int64))] = &account{email: email, status: UserStatusActive}
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
