package recording

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/schema"
	"github.com/nauticana/keel/storage"
	"github.com/nauticana/keel/user"
)

func TestMain(m *testing.M) {
	schema.LoadTestConfig()
	m.Run()
}

// memStore is an in-memory stand-in for the recording tables, driven by query name.
type memStore struct {
	sessions     map[int64][]any // selectSessionFields order
	participants map[int64][][]any
	media        map[int64][]any // selectMediaFields order, then completed_at
	invites      map[string][]any
	nextID       int64
	commits      int
}

func newMemStore() *memStore {
	return &memStore{sessions: map[int64][]any{}, participants: map[int64][][]any{}, media: map[int64][]any{}, invites: map[string][]any{}}
}

func (m *memStore) GenID() int64                   { m.nextID++; return m.nextID }
func (m *memStore) Commit(context.Context) error   { m.commits++; return nil }
func (m *memStore) Rollback(context.Context) error { return nil }

func (m *memStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	out := &model.QueryResult{}
	switch name {
	case qInsertSession:
		m.sessions[args[0].(int64)] = []any{args[0], args[1], args[2], args[3], StatusAwaitingConsent, "", nil, args[4], int64(1), time.Now()}
	case qInsertParticipant:
		id := args[0].(int64)
		m.participants[id] = append(m.participants[id], []any{int64(args[1].(int)), args[2]})
	case qGetSession, qLockSession:
		if row, ok := m.sessions[args[0].(int64)]; ok {
			out.Rows = [][]any{row}
		}
	case qGetSessionByCtx:
		for _, row := range m.sessions {
			if row[1] == args[0] && row[2] == args[1] {
				out.Rows = [][]any{row}
			}
		}
	case qListParticipants:
		out.Rows = m.participants[args[0].(int64)]
	case qSetStatus:
		m.sessions[args[1].(int64)][4] = args[0]
	case qSetCapture:
		row := m.sessions[args[2].(int64)]
		row[5], row[6] = "", nil
		if args[0] != nil {
			row[5], row[6] = args[0], args[1]
		}
	case qReopen:
		row := m.sessions[args[0].(int64)]
		row[4], row[5], row[6], row[8] = StatusAwaitingConsent, "", nil, row[8].(int64)+1
	case qInsertInvite:
		m.invites[args[0].(string)] = []any{args[1], args[2]}
	case qInviteSession:
		if inv, ok := m.invites[args[0].(string)]; ok && inv[1].(time.Time).After(args[1].(time.Time)) {
			out.Rows = [][]any{{inv[0]}}
		}
	case qInsertMedia:
		m.media[args[0].(int64)] = []any{args[0], args[1], args[2], args[3], args[4], int64(0), MediaPending, nil}
	case qGetMediaByKey:
		for _, row := range m.media {
			if row[1] == args[0] && row[3] == args[1] {
				out.Rows = [][]any{row}
			}
		}
	case qResetMedia:
		row := m.media[args[2].(int64)]
		row[4], row[5], row[6], row[7] = args[0], int64(0), MediaPending, nil
	case qSetMediaStatus:
		row := m.media[args[3].(int64)]
		row[6], row[5] = args[0], args[1]
		if args[0] == MediaReady {
			row[7] = time.Now()
		}
	case qGetMedia:
		if row, ok := m.media[args[0].(int64)]; ok && row[1] == args[1] {
			out.Rows = [][]any{row}
		}
	case qGetMediaByID:
		if row, ok := m.media[args[0].(int64)]; ok {
			out.Rows = [][]any{row}
		}
	case qListMedia:
		for id := int64(1); id <= m.nextID; id++ {
			if row, ok := m.media[id]; ok && row[1] == args[0] {
				out.Rows = append(out.Rows, row)
			}
		}
	case qMediaCounts:
		var ready, pending, failed int64
		for _, row := range m.media {
			if row[1] != args[0] {
				continue
			}
			switch row[6] {
			case MediaReady:
				ready++
			case MediaPending:
				pending++
			case MediaFailed:
				failed++
			}
		}
		out.Rows = [][]any{{ready, pending, failed}}
	case qSessionsWithDueMedia:
		seen := map[int64]bool{}
		for id := int64(1); id <= m.nextID; id++ {
			if row, ok := m.media[id]; ok && m.due(row, args[0]) && row[1].(int64) > args[1].(int64) && !seen[row[1].(int64)] {
				seen[row[1].(int64)] = true
				out.Rows = append(out.Rows, []any{row[1]})
			}
		}
	case qDueMedia:
		for id := int64(1); id <= m.nextID; id++ {
			if row, ok := m.media[id]; ok && row[1] == args[0] && m.due(row, args[1]) {
				out.Rows = append(out.Rows, row)
			}
		}
	case qSetMediaPurged:
		if row := m.media[args[0].(int64)]; row[6] == MediaReady {
			row[6] = MediaPurged
		}
	default:
		return nil, errors.New("unexpected query " + name)
	}
	return out, nil
}

func (m *memStore) due(row []any, cutoff any) bool {
	completed, ok := row[7].(time.Time)
	return row[6] == MediaReady && ok && completed.Before(cutoff.(time.Time))
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

type memConsents struct {
	user.ConsentService
	decisions map[string]bool // user:eventRef → consented
}

func (c *memConsents) Record(_ context.Context, req user.ConsentRequest) error {
	c.decisions[consentKey(req.UserID, req.EventRef)] = req.Consented
	return nil
}
func (c *memConsents) Withdraw(ctx context.Context, req user.ConsentRequest) error {
	return c.Record(ctx, req)
}
func (c *memConsents) LatestConsentFor(_ context.Context, userID int, _, eventRef string, _ int64) (bool, bool, error) {
	v, ok := c.decisions[consentKey(userID, eventRef)]
	return v, ok, nil
}
func (c *memConsents) ResolvePolicyID(context.Context, user.ConsentPolicyRef) (int64, error) {
	return 1, nil
}
func consentKey(userID int, ref string) string { return fmt.Sprintf("%d:%s", userID, ref) }

type memStorage struct {
	storage.ObjectStorage
	uploaded map[string]int64
	deleted  []string
	fail     bool
}

func (s *memStorage) PutObject(_ context.Context, key string, r io.Reader, _ string, _ map[string]string) error {
	if s.fail {
		return errors.New("bucket unavailable")
	}
	b, _ := io.ReadAll(r)
	s.uploaded[key] = int64(len(b))
	return nil
}
func (s *memStorage) Bucket() string { return "rec" }
func (s *memStorage) DeleteObject(_ context.Context, key string) error {
	s.deleted = append(s.deleted, key)
	return nil
}
func (s *memStorage) GetSignedURL(_ context.Context, key string, _ int) (string, error) {
	return "https://signed/" + s.Bucket() + "/" + key, nil
}

func newService(t *testing.T) (*Service, *memStore, *memConsents, *memStorage) {
	t.Helper()
	store := newMemStore()
	consents := &memConsents{decisions: map[string]bool{}}
	stor := &memStorage{uploaded: map[string]int64{}}
	return &Service{DB: memRepo{store: store}, Consents: consents, Storage: stor, MaxMediaBytes: 1024, AllowedContentType: map[string]bool{"video/mp4": true}}, store, consents, stor
}

// readySession drives a single-participant session to recording and returns its capture token.
func readySession(t *testing.T, svc *Service, contextRef string) (*Session, string) {
	t.Helper()
	ctx := context.Background()
	s, err := svc.CreateSession(ctx, 1, contextRef, "", testPolicy, 1, []Participant{{1, "a"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Decide(ctx, s.ID, 1, true, user.ConsentRequest{}); err != nil {
		t.Fatal(err)
	}
	token, _, err := svc.Start(ctx, s.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Acknowledge(ctx, s.ID, 1, token); err != nil {
		t.Fatal(err)
	}
	return s, token
}
