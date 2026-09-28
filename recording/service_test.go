package recording

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/user"
)

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

func TestReopen_RequiresFreshConsentAndKeepsMedia(t *testing.T) {
	svc, _, _, _ := newService(t)
	ctx := context.Background()
	s, token := readySession(t, svc, "order:8")
	media, _ := svc.Upload(ctx, s.ID, 1, token, "clip", "video/mp4", strings.NewReader("x"))
	if _, err := svc.Reopen(ctx, s.ID, 1); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("reopen while recording: %v", err)
	}
	_ = svc.Stop(ctx, s.ID, 1)
	if _, err := svc.Reopen(ctx, s.ID, 9); !errors.Is(err, ErrForbidden) {
		t.Fatalf("outsider reopen: %v", err)
	}
	reopened, err := svc.Reopen(ctx, s.ID, 1)
	if err != nil || reopened.Status != StatusAwaitingConsent || reopened.Attempt != 2 {
		t.Fatalf("reopen: %+v err=%v", reopened, err)
	}
	if _, _, err := svc.Start(ctx, s.ID, 1); !errors.Is(err, ErrConsentMissing) {
		t.Fatalf("earlier attempt's consent must not authorize: %v", err)
	}
	_ = svc.Decide(ctx, s.ID, 1, true, user.ConsentRequest{})
	if _, _, err := svc.Start(ctx, s.ID, 1); err != nil {
		t.Fatal(err)
	}
	if url, err := svc.MediaURL(ctx, s.ID, 1, media.ID, 60); err != nil || url == "" {
		t.Fatalf("media must survive reopen: %v", err)
	}
}

func TestJoinWithConsent_AddsConsentedParticipant(t *testing.T) {
	svc, store, consents, _ := newService(t)
	ctx := context.Background()
	s, _ := svc.CreateSession(ctx, 1, "order:9", "", testPolicy, 1, []Participant{{1, "a"}})
	if _, _, err := svc.Invite(ctx, s.ID, 9, time.Minute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("outsider invite: %v", err)
	}
	token, exp, err := svc.Invite(ctx, s.ID, 1, time.Minute)
	if err != nil || token == "" || exp.Before(time.Now()) {
		t.Fatalf("invite: %v", err)
	}
	if _, err := svc.InviteSession(ctx, "bogus"); !errors.Is(err, ErrInviteToken) {
		t.Fatalf("bogus token: %v", err)
	}
	if preview, err := svc.InviteSession(ctx, token); err != nil || preview.ID != s.ID {
		t.Fatalf("preview: %+v err=%v", preview, err)
	}
	joined, err := svc.JoinWithConsent(ctx, token, 5, "guest", user.ConsentRequest{})
	if err != nil || len(joined.Participants) != 2 || !consents.decisions[consentKey(5, EventRef(s.ID, 1))] {
		t.Fatalf("join: %+v err=%v", joined, err)
	}
	if again, err := svc.JoinWithConsent(ctx, token, 5, "other", user.ConsentRequest{}); err != nil || len(again.Participants) != 2 {
		t.Fatalf("join must be idempotent: %+v err=%v", again, err)
	}
	_ = svc.Decide(ctx, s.ID, 1, true, user.ConsentRequest{})
	if _, _, err := svc.Start(ctx, s.ID, 5); err != nil {
		t.Fatalf("joined participant starts: %v", err)
	}
	_ = svc.Stop(ctx, s.ID, 1)
	if _, err := svc.JoinWithConsent(ctx, token, 6, "guest", user.ConsentRequest{}); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("join after stop: %v", err)
	}
	store.invites[sha256Hex(token)][1] = time.Now().Add(-time.Second)
	if _, err := svc.InviteSession(ctx, token); !errors.Is(err, ErrInviteToken) {
		t.Fatalf("expired token: %v", err)
	}
}

func TestUpload_ObjectKeyOverride(t *testing.T) {
	svc, _, _, stor := newService(t)
	ctx := context.Background()
	svc.ObjectKey = func(s Session, key string) string {
		return fmt.Sprintf("recording/%s/%d/%s", s.CreatedAt.Format("20060102"), s.ID, key)
	}
	s, token := readySession(t, svc, "order:10")
	media, err := svc.Upload(ctx, s.ID, 1, token, "clip", "video/mp4", strings.NewReader("x"))
	want := fmt.Sprintf("recording/%s/%d/clip", s.CreatedAt.Format("20060102"), s.ID)
	if err != nil || media.ObjectKey != want || stor.uploaded[want] != 1 {
		t.Fatalf("media=%+v err=%v", media, err)
	}
	svc.ObjectKey = func(Session, string) string { return "recording/../escape" }
	if _, err := svc.Upload(ctx, s.ID, 1, token, "other", "video/mp4", strings.NewReader("x")); err == nil {
		t.Fatal("key outside recording/ accepted")
	}
}

func TestPrivilegedMediaAccess(t *testing.T) {
	svc, _, _, _ := newService(t)
	ctx := context.Background()
	s, token := readySession(t, svc, "order:11")
	ready, _ := svc.Upload(ctx, s.ID, 1, token, "clip", "video/mp4", strings.NewReader("x"))
	list, err := svc.ListMedia(ctx, s.ID)
	if err != nil || len(list) != 1 || list[0].ID != ready.ID || list[0].CompletedAt.IsZero() {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if _, err := svc.ListMedia(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown session: %v", err)
	}
	if url, err := svc.PrivilegedMediaURL(ctx, ready.ID, 60); err != nil || url != "https://signed/rec/"+ready.ObjectKey {
		t.Fatalf("url=%s err=%v", url, err)
	}
	if _, err := svc.PrivilegedMediaURL(ctx, 999, 60); !errors.Is(err, ErrMediaNotFound) {
		t.Fatalf("unknown media: %v", err)
	}
}
