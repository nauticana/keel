package notify

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/schema"
)

func TestMain(m *testing.M) {
	schema.LoadTestConfig()
	m.Run()
}

// memRow mirrors a notification row, in claim RETURNING order where it overlaps.
type memRow struct {
	id, partnerID                          any
	userID                                 int
	notificationType, channel, title, body string
	data                                   any
	status                                 string
	attempts                               int64
	leaseToken                             int64
	lastError                              string
	delay                                  int
}

// memStore is an in-memory stand-in for the notification tables, driven by query name.
type memStore struct {
	rows      map[int64]*memRow
	prefs     map[[3]any]bool // user, type, channel → enabled
	nextID    int64
	commits   int
	rollbacks int
	failOn    string // query name that returns an error
}

func newMemStore() *memStore {
	return &memStore{rows: map[int64]*memRow{}, prefs: map[[3]any]bool{}, nextID: 100}
}

func (m *memStore) GenID() int64                   { m.nextID++; return m.nextID }
func (m *memStore) Commit(context.Context) error   { m.commits++; return nil }
func (m *memStore) Rollback(context.Context) error { m.rollbacks++; return nil }

func (m *memStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	if name == m.failOn {
		return nil, errors.New("injected failure on " + name)
	}
	out := &model.QueryResult{}
	switch name {
	case qTypePreferences:
		var channels []string
		for k := range m.prefs {
			if k[0] == args[0] && k[1] == args[1] {
				channels = append(channels, k[2].(string))
			}
		}
		sort.Strings(channels)
		for _, c := range channels {
			out.Rows = append(out.Rows, []any{c, m.prefs[[3]any{args[0], args[1], c}]})
		}
	case qUserPreferences:
		for k, enabled := range m.prefs {
			if k[0] == args[0] {
				out.Rows = append(out.Rows, []any{k[1], k[2], enabled})
			}
		}
		sort.Slice(out.Rows, func(i, j int) bool {
			return out.Rows[i][0].(string)+out.Rows[i][1].(string) < out.Rows[j][0].(string)+out.Rows[j][1].(string)
		})
	case qSetPreference:
		m.prefs[[3]any{args[0], args[1], args[2]}] = args[3].(bool)
	case qInsert:
		m.rows[args[0].(int64)] = &memRow{id: args[0], userID: args[1].(int), partnerID: args[2],
			notificationType: args[3].(string), channel: args[4].(string), title: args[5].(string),
			body: asStr(args[6]), data: args[7], status: StatusPending}
	case qPending:
		var ids []int64
		for id, r := range m.rows {
			if r.status == StatusPending && r.delay == 0 {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			out.Rows = append(out.Rows, []any{id})
		}
	case qClaim:
		if r, ok := m.rows[args[1].(int64)]; ok && r.status == StatusPending {
			r.status, r.leaseToken = StatusActive, args[0].(int64)
			out.Rows = [][]any{{r.id, int64(r.userID), r.partnerID, r.notificationType, r.channel, r.title, r.body, r.data, r.attempts, r.leaseToken}}
		}
	case qReclaim:
	case qSent, qSuppressed, qRetry, qFail:
		id, token := args[len(args)-2].(int64), args[len(args)-1].(int64)
		r, ok := m.rows[id]
		if !ok || r.leaseToken != token {
			return out, nil
		}
		r.attempts++
		r.leaseToken = 0
		switch name {
		case qSent:
			r.status = StatusSent
		case qSuppressed:
			r.status, r.lastError = StatusSuppressed, args[0].(string)
		case qRetry:
			r.status, r.delay, r.lastError = StatusPending, args[0].(int), args[1].(string)
		case qFail:
			r.status, r.lastError = StatusFailed, args[0].(string)
		}
		out.Rows = [][]any{{id}}
	default:
		return nil, errors.New("unexpected query " + name)
	}
	return out, nil
}

func asStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (m *memStore) byChannel(channel string) *memRow {
	for _, r := range m.rows {
		if r.channel == channel {
			return r
		}
	}
	return nil
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

// fakeSender records requests and answers each channel with a scripted error.
type fakeSender struct {
	errs map[string]error
	got  []port.NotificationRequest
}

func (s *fakeSender) Send(_ context.Context, req port.NotificationRequest) error {
	s.got = append(s.got, req)
	return s.errs[req.Channel]
}

type fakeLogger struct{ warnings, errors []string }

func (*fakeLogger) Initialize(string, string) error { return nil }
func (*fakeLogger) Close()                          {}
func (*fakeLogger) Access(string)                   {}
func (*fakeLogger) Info(string)                     {}
func (l *fakeLogger) Warning(s string)              { l.warnings = append(l.warnings, s) }
func (l *fakeLogger) Error(s string)                { l.errors = append(l.errors, s) }
func (*fakeLogger) Fatal(string)                    {}

var (
	_ port.TxQueryService      = (*memStore)(nil)
	_ port.NotificationService = (*fakeSender)(nil)
)
