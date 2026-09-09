package recording

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// memStore is an in-memory stand-in for the recording tables, driven by query name.
type memStore struct {
	sessions     map[int64][]any // id, partner, ctx, consent_type, status, hash, expires
	participants map[int64][][]any
	media        map[int64][]any // id, session, bucket, key, ctype, size, status
	nextID       int64
	commits      int
}

func (m *memStore) GenID() int64                   { m.nextID++; return m.nextID }
func (m *memStore) Commit(context.Context) error   { m.commits++; return nil }
func (m *memStore) Rollback(context.Context) error { return nil }

func (m *memStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	out := &model.QueryResult{}
	switch name {
	case qInsertSession:
		m.sessions[args[0].(int64)] = []any{args[0], args[1], args[2], args[3], StatusAwaitingConsent, "", nil, args[4]}
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
	case qInsertMedia:
		m.media[args[0].(int64)] = []any{args[0], args[1], args[2], args[3], args[4], int64(0), MediaPending}
	case qGetMediaByKey:
		for _, row := range m.media {
			if row[1] == args[0] && row[3] == args[1] {
				out.Rows = [][]any{row}
			}
		}
	case qResetMedia:
		row := m.media[args[2].(int64)]
		row[4], row[5], row[6] = args[0], int64(0), MediaPending
	case qSetMediaStatus:
		row := m.media[args[3].(int64)]
		row[6], row[5] = args[0], args[1]
	case qGetMedia:
		if row, ok := m.media[args[0].(int64)]; ok && row[1] == args[1] {
			out.Rows = [][]any{row}
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
	return r.store, nil
}

type memConsents struct {
	user.ConsentService
	decisions map[string]bool // user:eventRef → consented
}

func (c *memConsents) Record(_ context.Context, req user.ConsentRequest) error {
	c.decisions[key(req.UserID, req.EventRef)] = req.Consented
	return nil
}
func (c *memConsents) Withdraw(ctx context.Context, req user.ConsentRequest) error {
	return c.Record(ctx, req)
}
func (c *memConsents) LatestConsentFor(_ context.Context, userID int, _, eventRef string, _ int64) (bool, bool, error) {
	v, ok := c.decisions[key(userID, eventRef)]
	return v, ok, nil
}
func (c *memConsents) ResolvePolicyID(context.Context, user.ConsentPolicyRef) (int64, error) {
	return 1, nil
}
func key(userID int, ref string) string {
	return strings.Join([]string{string(rune('0' + userID)), ref}, ":")
}

type memStorage struct {
	uploaded map[string]int64
	fail     bool
}

func (s *memStorage) Upload(_ context.Context, _, key string, r io.Reader, _ string) error {
	if s.fail {
		return errors.New("bucket unavailable")
	}
	b, _ := io.ReadAll(r)
	s.uploaded[key] = int64(len(b))
	return nil
}
func (s *memStorage) Download(context.Context, string, string) (io.ReadCloser, error) {
	return nil, nil
}
func (s *memStorage) Delete(context.Context, string, string) error { return nil }
func (s *memStorage) GetSignedURL(_ context.Context, bucket, key string, _ int) (string, error) {
	return "https://signed/" + bucket + "/" + key, nil
}
func (s *memStorage) PublicURL(bucket, key string) string { return "" }

func newService(t *testing.T) (*Service, *memStore, *memConsents, *memStorage) {
	t.Helper()
	store := &memStore{sessions: map[int64][]any{}, participants: map[int64][][]any{}, media: map[int64][]any{}}
	consents := &memConsents{decisions: map[string]bool{}}
	stor := &memStorage{uploaded: map[string]int64{}}
	return &Service{DB: memRepo{store: store}, Consents: consents, Storage: stor, Bucket: "rec", MaxMediaBytes: 1024, AllowedContentType: map[string]bool{"video/mp4": true}}, store, consents, stor
}

var testPolicy = user.ConsentPolicyRef{Type: "video", Region: "US", Version: "1", Language: "en"}

func TestStart_RequiresEveryParticipantConsent(t *testing.T) {
	svc, _, _, _ := newService(t)
	ctx := context.Background()
	s, err := svc.CreateSession(ctx, 1, "order:42", "", testPolicy, 1, []Participant{{1, "a"}, {2, "b"}})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := svc.CreateSession(ctx, 1, "order:42", "", testPolicy, 1, []Participant{{1, "a"}})
	if again.ID != s.ID || len(again.Participants) != 2 {
		t.Fatalf("create is not idempotent: %+v", again)
	}
	if _, _, err := svc.Start(ctx, s.ID, 1); !errors.Is(err, ErrConsentMissing) {
		t.Fatalf("no consent: %v", err)
	}
	if err := svc.Decide(ctx, s.ID, 1, true, user.ConsentRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Start(ctx, s.ID, 1); !errors.Is(err, ErrConsentMissing) {
		t.Fatalf("one consent: %v", err)
	}
	if err := svc.Decide(ctx, s.ID, 9, true, user.ConsentRequest{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("outsider decide: %v", err)
	}
	_ = svc.Decide(ctx, s.ID, 2, true, user.ConsentRequest{})
	token, exp, err := svc.Start(ctx, s.ID, 2)
	if err != nil || token == "" || exp.Before(time.Now()) {
		t.Fatalf("start: token=%q exp=%v err=%v", token, exp, err)
	}
	got, _ := svc.GetSession(ctx, s.ID, 1)
	if got.Status != StatusAuthorized {
		t.Fatalf("status=%s", got.Status)
	}
}

func TestLifecycle_AcknowledgeUploadStopReady(t *testing.T) {
	svc, _, _, stor := newService(t)
	ctx := context.Background()
	s, _ := svc.CreateSession(ctx, 1, "order:1", "", testPolicy, 1, []Participant{{1, "a"}})
	_ = svc.Decide(ctx, s.ID, 1, true, user.ConsentRequest{})
	token, _, _ := svc.Start(ctx, s.ID, 1)

	if err := svc.Acknowledge(ctx, s.ID, 1, "wrong"); !errors.Is(err, ErrCaptureToken) {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := svc.Upload(ctx, s.ID, 1, token, "clip1", "video/mp4", bytes.NewReader([]byte("abc"))); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("upload before ack: %v", err)
	}
	if err := svc.Acknowledge(ctx, s.ID, 1, token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Renew(ctx, s.ID, 1, token); err != nil {
		t.Fatal(err)
	}
	media, err := svc.Upload(ctx, s.ID, 1, token, "clip1", "video/mp4", bytes.NewReader([]byte("abc")))
	if err != nil || media.Status != MediaReady || media.SizeBytes != 3 || stor.uploaded["recording/1/clip1"] != 3 {
		t.Fatalf("upload: %+v err=%v", media, err)
	}
	if err := svc.Stop(ctx, s.ID, 1); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.GetSession(ctx, s.ID, 1)
	if got.Status != StatusReady {
		t.Fatalf("status after stop=%s", got.Status)
	}
	if err := svc.Stop(ctx, s.ID, 1); err != nil {
		t.Fatalf("stop must be idempotent: %v", err)
	}
	if err := svc.Acknowledge(ctx, s.ID, 1, token); !errors.Is(err, ErrCaptureToken) {
		t.Fatalf("token must be cleared after stop: %v", err)
	}
	url, err := svc.MediaURL(ctx, s.ID, 1, media.ID, 60)
	if err != nil || url != "https://signed/rec/recording/1/clip1" {
		t.Fatalf("url=%s err=%v", url, err)
	}
	if _, err := svc.MediaURL(ctx, s.ID, 9, media.ID, 60); !errors.Is(err, ErrForbidden) {
		t.Fatalf("outsider url: %v", err)
	}
}

func TestStop_BeforeCaptureAndUploadAfterStopReachesReady(t *testing.T) {
	svc, _, _, _ := newService(t)
	ctx := context.Background()
	s, _ := svc.CreateSession(ctx, 1, "order:2", "", testPolicy, 1, []Participant{{1, "a"}})
	_ = svc.Decide(ctx, s.ID, 1, true, user.ConsentRequest{})
	_, _, _ = svc.Start(ctx, s.ID, 1)
	_ = svc.Stop(ctx, s.ID, 1)
	if got, _ := svc.GetSession(ctx, s.ID, 1); got.Status != StatusStopped {
		t.Fatalf("never-captured stop status=%s", got.Status)
	}

	s2, _ := svc.CreateSession(ctx, 1, "order:3", "", testPolicy, 1, []Participant{{1, "a"}})
	_ = svc.Decide(ctx, s2.ID, 1, true, user.ConsentRequest{})
	token, _, _ := svc.Start(ctx, s2.ID, 1)
	_ = svc.Acknowledge(ctx, s2.ID, 1, token)
	if err := svc.Decide(ctx, s2.ID, 1, false, user.ConsentRequest{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.GetSession(ctx, s2.ID, 1); got.Status != StatusFinalizing {
		t.Fatalf("withdraw while recording status=%s", got.Status)
	}
	if _, _, err := svc.Start(ctx, s2.ID, 1); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("restart after withdraw: %v", err)
	}
}

func TestUpload_FailureStaysFailed(t *testing.T) {
	svc, _, _, stor := newService(t)
	ctx := context.Background()
	s, _ := svc.CreateSession(ctx, 1, "order:4", "", testPolicy, 1, []Participant{{1, "a"}})
	_ = svc.Decide(ctx, s.ID, 1, true, user.ConsentRequest{})
	token, _, _ := svc.Start(ctx, s.ID, 1)
	_ = svc.Acknowledge(ctx, s.ID, 1, token)
	stor.fail = true
	media, err := svc.Upload(ctx, s.ID, 1, token, "clip", "video/mp4", bytes.NewReader([]byte("x")))
	if err == nil || media.Status != MediaFailed {
		t.Fatalf("media=%+v err=%v", media, err)
	}
	if _, err := svc.MediaURL(ctx, s.ID, 1, media.ID, 60); !errors.Is(err, ErrMediaNotReady) {
		t.Fatalf("failed media url: %v", err)
	}
	stor.fail = false
	retried, err := svc.Upload(ctx, s.ID, 1, token, "clip", "video/mp4", bytes.NewReader([]byte("ok")))
	if err != nil || retried.ID != media.ID || retried.Status != MediaReady {
		t.Fatalf("retry=%+v err=%v", retried, err)
	}
	_ = svc.Stop(ctx, s.ID, 1)
	if got, _ := svc.GetSession(ctx, s.ID, 1); got.Status != StatusReady {
		t.Fatalf("retried media must become ready: %s", got.Status)
	}
}

func TestUpload_ValidatesActorSizeAndKey(t *testing.T) {
	svc, _, _, _ := newService(t)
	ctx := context.Background()
	s, _ := svc.CreateSession(ctx, 1, "order:5", "", testPolicy, 1, []Participant{{1, "a"}})
	_ = svc.Decide(ctx, s.ID, 1, true, user.ConsentRequest{})
	token, _, _ := svc.Start(ctx, s.ID, 1)
	_ = svc.Acknowledge(ctx, s.ID, 1, token)
	if _, err := svc.Upload(ctx, s.ID, 9, token, "clip", "video/mp4", strings.NewReader("x")); !errors.Is(err, ErrForbidden) {
		t.Fatalf("outsider upload: %v", err)
	}
	if _, err := svc.Upload(ctx, s.ID, 1, token, "../clip", "video/mp4", strings.NewReader("x")); err == nil {
		t.Fatal("unsafe key accepted")
	}
	svc.MaxMediaBytes = 1
	if _, err := svc.Upload(ctx, s.ID, 1, token, "large", "video/mp4", strings.NewReader("xx")); !errors.Is(err, ErrMediaTooLarge) {
		t.Fatalf("oversize upload: %v", err)
	}
}

func TestCreateSession_CreatorNeedNotParticipateAndMismatchConflicts(t *testing.T) {
	svc, _, _, _ := newService(t)
	ctx := context.Background()
	s, err := svc.CreateSession(ctx, 1, "order:6", "", testPolicy, 99, []Participant{{1, "a"}, {2, "b"}})
	if err != nil {
		t.Fatalf("system creator rejected: %v", err)
	}
	if _, err := svc.GetSession(ctx, s.ID, 99); !errors.Is(err, ErrForbidden) {
		t.Fatalf("creator must not gain participant access: %v", err)
	}
	if _, err := svc.CreateSession(ctx, 1, "order:6", "other_type", testPolicy, 99, []Participant{{1, "a"}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("different terms: %v", err)
	}
}

func TestUpload_ParentKeyRejectedAndFailedMediaDoesNotBlockReady(t *testing.T) {
	svc, _, _, stor := newService(t)
	ctx := context.Background()
	s, _ := svc.CreateSession(ctx, 1, "order:7", "", testPolicy, 1, []Participant{{1, "a"}})
	_ = svc.Decide(ctx, s.ID, 1, true, user.ConsentRequest{})
	token, _, _ := svc.Start(ctx, s.ID, 1)
	_ = svc.Acknowledge(ctx, s.ID, 1, token)
	if _, err := svc.Upload(ctx, s.ID, 1, token, "..", "video/mp4", strings.NewReader("x")); err == nil {
		t.Fatal("parent key accepted")
	}
	stor.fail = true
	_, _ = svc.Upload(ctx, s.ID, 1, token, "bad", "video/mp4", strings.NewReader("x"))
	stor.fail = false
	if _, err := svc.Upload(ctx, s.ID, 1, token, "good", "video/mp4", strings.NewReader("ok")); err != nil {
		t.Fatal(err)
	}
	_ = svc.Stop(ctx, s.ID, 1)
	if got, _ := svc.GetSession(ctx, s.ID, 1); got.Status != StatusReady {
		t.Fatalf("a failed clip must not block ready: %s", got.Status)
	}
}
