package domain

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/guard"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/schema"
)

func TestMain(m *testing.M) {
	schema.LoadTestConfig()
	m.Run()
}

type vrow struct {
	partner                    int64
	url                        string
	at                         time.Time
	name, method               string
	by                         int64
	tokenHash, ref             string
	checked                    time.Time
	held                       time.Time
	failing, lapsed, cancelled time.Time
	cancelledBy                int64
	lastErr                    string
}

func (r *vrow) current() bool { return r.lapsed.IsZero() && r.cancelled.IsZero() }

func (r *vrow) heldWithin(now time.Time, seconds any) bool {
	return r.current() && r.held.After(now.Add(-time.Duration(seconds.(int))*time.Second))
}

type chrow struct {
	hash, recipient string
	issued, expires time.Time
	attempts        int64
}

type state struct {
	domains    map[string]bool // partner|url
	members    map[[2]int64]bool
	rows       []*vrow
	challenges map[string]*chrow // partner|url|method
}

// memStore stands in for the two verification tables plus the partner_domain
// and partner_user reads, driven by query name, on a fake clock.
type memStore struct {
	state
	now      time.Time
	stmt     int64
	snapshot *state
	queries  []string
}

func newStore() *memStore {
	return &memStore{
		state: state{domains: map[string]bool{}, members: map[[2]int64]bool{}, challenges: map[string]*chrow{}},
		now:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func (m *memStore) addDomain(partner int64, url string, users ...int64) {
	m.domains[key(partner, url)] = true
	for _, u := range users {
		m.members[[2]int64{partner, u}] = true
	}
}

func (m *memStore) tick(d time.Duration) { m.now = m.now.Add(d) }

func key(parts ...any) string { return fmt.Sprint(parts...) }

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func nullStr(v any) string {
	s, _ := v.(string)
	return s
}

func (r *vrow) fields() []any {
	return []any{r.partner, r.url, r.at, r.name, r.method, r.by, r.ref, r.checked,
		nullTime(r.failing), r.lastErr, nullTime(r.lapsed), nullTime(r.cancelled), r.cancelledBy, r.held}
}

func (m *memStore) find(partner int64, url string, at time.Time) *vrow {
	for _, r := range m.rows {
		if r.partner == partner && r.url == url && r.at.Equal(at) && r.current() {
			return r
		}
	}
	return nil
}

func (m *memStore) GenID() int64 { return 0 }

func (m *memStore) Commit(context.Context) error { m.snapshot = nil; return nil }

func (m *memStore) Rollback(context.Context) error {
	if m.snapshot != nil {
		m.state = *m.snapshot
		m.snapshot = nil
	}
	return nil
}

func (m *memStore) begin() {
	cp := state{domains: m.domains, members: m.members, challenges: map[string]*chrow{}}
	for _, r := range m.rows {
		c := *r
		cp.rows = append(cp.rows, &c)
	}
	for k, c := range m.challenges {
		cc := *c
		cp.challenges[k] = &cc
	}
	m.snapshot = &cp
}

func (m *memStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	m.queries = append(m.queries, name)
	out := &model.QueryResult{}
	switch name {
	case qDomain:
		if m.domains[key(args[0], args[1])] {
			out.Rows = [][]any{{args[1]}}
		}
	case qMember:
		if m.members[[2]int64{args[0].(int64), args[1].(int64)}] {
			out.Rows = [][]any{{1}}
		}
	case guard.QueryLock:
	case qOtherHolders:
		for _, r := range m.rows {
			if r.heldWithin(m.now, args[3]) && r.name == args[0] && slices.Contains(args[1].([]string), r.method) && r.partner != args[2] {
				out.Rows = [][]any{{r.partner}}
			}
		}
	case qSupersede:
		for _, r := range m.rows {
			if r.current() && r.name == args[0] && slices.Contains(args[1].([]string), r.method) && r.partner != args[2] {
				r.lapsed, r.lastErr = m.now, "superseded by another partner"
			}
		}
	case qIdentityHolders:
		seen := map[int64]bool{}
		for _, r := range m.rows {
			if r.heldWithin(m.now, args[2]) && r.name == args[0] && slices.Contains(args[1].([]string), r.method) && !seen[r.partner] {
				seen[r.partner] = true
				out.Rows = append(out.Rows, []any{r.partner})
			}
		}
	case qCurrentSame:
		for _, r := range m.rows {
			if r.current() && r.partner == args[0] && r.url == args[1] && r.method == args[2] {
				out.Rows = [][]any{{r.at}}
			}
		}
	case qRefresh:
		for _, r := range m.rows {
			if r.current() && r.partner == args[2] && r.url == args[3] && r.method == args[4] {
				r.checked, r.held, r.failing, r.lastErr, r.tokenHash, r.ref = m.now, m.now, time.Time{}, "", nullStr(args[0]), nullStr(args[1])
			}
		}
	case qInsert:
		// CURRENT_TIMESTAMP is the transaction start; clock_timestamp() advances per statement.
		at := m.now
		if strings.Contains(queries[qInsert], "clock_timestamp()") {
			m.stmt++
			at = m.now.Add(time.Duration(m.stmt) * time.Microsecond)
		}
		for _, r := range m.rows {
			if r.partner == args[0] && r.url == args[1] && r.at.Equal(at) {
				return nil, errors.New("duplicate key value violates unique constraint partner_domain_verification_pk")
			}
		}
		m.rows = append(m.rows, &vrow{partner: args[0].(int64), url: args[1].(string), at: at, name: args[2].(string),
			method: args[3].(string), by: args[4].(int64), tokenHash: nullStr(args[5]), ref: nullStr(args[6]), checked: m.now, held: m.now})
	case qGetCurrent:
		for _, r := range m.rows {
			if r.current() && r.partner == args[0] && r.url == args[1] && r.method == args[2] {
				out.Rows = [][]any{r.fields()}
			}
		}
	case qCurrent:
		for _, r := range m.rows {
			if r.current() && r.partner == args[0] && r.url == args[1] && slices.Contains(args[2].([]string), r.method) {
				out.Rows = append(out.Rows, r.fields())
			}
		}
	case qPartnerCurrent:
		for _, r := range m.rows {
			if r.current() && r.partner == args[0] && slices.Contains(args[1].([]string), r.method) {
				out.Rows = append(out.Rows, r.fields())
			}
		}
	case qHistory:
		for i := len(m.rows) - 1; i >= 0; i-- {
			if r := m.rows[i]; r.partner == args[0] && r.url == args[1] && len(out.Rows) < args[2].(int) {
				out.Rows = append(out.Rows, r.fields())
			}
		}
	case qHolders:
		seen := map[int64]bool{}
		for _, r := range m.rows {
			if r.current() && r.name == args[0] && slices.Contains(args[1].([]string), r.method) && !seen[r.partner] {
				seen[r.partner] = true
				out.Rows = append(out.Rows, []any{r.partner})
			}
		}
	case qCancel:
		for _, r := range m.rows {
			if r.current() && r.partner == args[1] && r.url == args[2] && (args[3] == "" || r.method == args[4]) {
				r.cancelled, r.cancelledBy = m.now, args[0].(int64)
				out.Rows = append(out.Rows, []any{r.method})
			}
		}
	case qIssueChallenge:
		k := key(args[0], args[1], args[2])
		cooldown := time.Duration(args[7].(int)) * time.Second
		if c, ok := m.challenges[k]; ok && c.issued.After(m.now.Add(-cooldown)) {
			break
		}
		c := &chrow{hash: args[3].(string), recipient: nullStr(args[4]), issued: m.now,
			expires: m.now.Add(time.Duration(args[6].(int)) * time.Second)}
		m.challenges[k] = c
		out.Rows = [][]any{{c.expires}}
	case qAttemptChallenge:
		if c, ok := m.challenges[key(args[1], args[2], args[3])]; ok && c.expires.After(m.now) {
			if cap := int64(args[0].(int)); c.attempts < cap {
				c.attempts++
			}
			out.Rows = [][]any{{c.attempts, c.hash}}
		}
	case qDeleteChallenge:
		delete(m.challenges, key(args[0], args[1], args[2]))
	case qDue:
		interval := time.Duration(args[1].(int)) * time.Second
		for _, r := range m.rows {
			if r.current() && slices.Contains(args[0].([]string), r.method) && !r.checked.After(m.now.Add(-interval)) && len(out.Rows) < args[2].(int) {
				out.Rows = append(out.Rows, append(r.fields(), r.tokenHash))
			}
		}
	case qCheckHeld:
		if r := m.find(args[0].(int64), args[1].(string), args[2].(time.Time)); r != nil {
			r.checked, r.held, r.failing, r.lastErr = m.now, m.now, time.Time{}, ""
		}
	case qCheckFailed:
		if r := m.find(args[2].(int64), args[3].(string), args[4].(time.Time)); r != nil {
			if r.failing.IsZero() {
				r.failing = m.now
			}
			r.checked, r.lastErr = m.now, args[0].(string)
			if !r.failing.After(m.now.Add(-time.Duration(args[1].(int)) * time.Second)) {
				r.lapsed = m.now
			}
			out.Rows = [][]any{{nullTime(r.lapsed)}}
		}
	case qCheckError:
		if r := m.find(args[1].(int64), args[2].(string), args[3].(time.Time)); r != nil {
			r.checked, r.lastErr = m.now, args[0].(string)
		}
	default:
		panic("unexpected query " + name)
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
	r.store.begin()
	return r.store, nil
}

// fakeVerifier returns a scripted verdict and records the proofs it saw.
type fakeVerifier struct {
	method string
	err    error
	ref    string
	proofs []DomainProof
}

func (f *fakeVerifier) Method() string { return f.method }

func (f *fakeVerifier) Verify(_ context.Context, p DomainProof) (string, error) {
	f.proofs = append(f.proofs, p)
	return f.ref, f.err
}
