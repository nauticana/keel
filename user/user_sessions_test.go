package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
)

func withSessionConfig(t *testing.T, notify, stepUp bool, maxSessions int) {
	t.Helper()
	previous := config.Config()
	next := *previous
	next.NotifyNewDeviceSignin, next.StepUpNewDevice, next.MaxSessionsPerUser = notify, stepUp, maxSessions
	config.SetConfig(&next)
	t.Cleanup(func() { config.SetConfig(previous) })
}

type recordingNotifier struct {
	notices []SessionDevice
	codes   []string
	err     error
}

func (n *recordingNotifier) NewDeviceSignIn(_ context.Context, _ *model.UserSession, d SessionDevice) error {
	n.notices = append(n.notices, d)
	return n.err
}
func (n *recordingNotifier) StepUpCode(_ context.Context, _ *model.UserSession, code string) error {
	n.codes = append(n.codes, code)
	return n.err
}

const deviceA, deviceB = "aaaa", "bbbb"

func signIn(t *testing.T, svc *LocalUserService, device string) (*model.UserSession, string) {
	t.Helper()
	session := &model.UserSession{Id: 7, SignInMethod: SignInPassword}
	token, err := svc.CreateRefreshToken(session, SessionDevice{UserAgent: "agent", ClientIP: "192.0.2.1", DeviceSecret: device})
	if err != nil {
		t.Fatal(err)
	}
	return session, token
}

func TestSessionIDSurvivesRotationAndListsOnce(t *testing.T) {
	store := memberStore()
	svc := newLocalUserService(t, store)
	session, token := signIn(t, svc, deviceA)
	if session.SessionID == 0 {
		t.Fatal("no session id")
	}
	rotated, err := svc.ValidateRefreshToken(token, SessionDevice{UserAgent: "agent/2", ClientIP: "192.0.2.9"})
	if err != nil || rotated.SessionID != session.SessionID {
		t.Fatalf("rotated = %+v, %v", rotated, err)
	}
	sessions, err := svc.Sessions(7)
	if err != nil || len(sessions) != 1 || sessions[0].ID != session.SessionID || sessions[0].ClientIP != "192.0.2.9" || sessions[0].UserAgent != "agent/2" {
		t.Fatalf("sessions = %+v, %v", sessions, err)
	}
	if t2 := store.tokens[sha256Hex(rotated.NewRefreshToken)]; t2.device != deviceHashOf(deviceA) {
		t.Fatal("rotation must keep the sign-in device")
	}
}

func TestRevokeSessionIsOwnerScoped(t *testing.T) {
	if !strings.Contains(LocalUserQueries[qRevokeSession], "expires_at > CURRENT_TIMESTAMP") {
		t.Fatal("expired sessions must not be revocable as active")
	}
	svc := newLocalUserService(t, memberStore())
	session, token := signIn(t, svc, deviceA)
	if err := svc.RevokeSession(8, session.SessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("another user's session = %v", err)
	}
	if err := svc.RevokeSession(7, session.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateRefreshToken(token, SessionDevice{}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("refresh of a revoked session = %v", err)
	}
	if err := svc.RevokeSession(7, session.SessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("second revoke = %v", err)
	}
}

func TestSessionCapEndsOldest(t *testing.T) {
	withSessionConfig(t, false, false, 2)
	store := memberStore()
	svc := newLocalUserService(t, store)
	first, firstToken := signIn(t, svc, deviceA)
	signIn(t, svc, deviceA)
	third, _ := signIn(t, svc, deviceB)
	if store.count("guard_xact_lock") != 3 {
		t.Fatalf("each capped sign-in must serialize per user: %v", store.calls)
	}
	sessions, _ := svc.Sessions(7)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	for _, s := range sessions {
		if s.ID == first.SessionID {
			t.Fatal("the oldest session must end")
		}
	}
	if _, err := svc.ValidateRefreshToken(firstToken, SessionDevice{}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("oldest still refreshes: %v", err)
	}
	if third.SessionID == 0 {
		t.Fatal("the new session must survive")
	}
}

func TestSignInNetworksEnforced(t *testing.T) {
	store := memberStore()
	store.networks[11] = []string{"192.0.2.0/24"}
	svc := newLocalUserService(t, store)
	session := &model.UserSession{Id: 7, PartnerId: 11, SignInMethod: SignInPassword}
	if _, err := svc.CreateRefreshToken(session, SessionDevice{ClientIP: "198.51.100.1"}); !errors.Is(err, ErrSignInNetwork) {
		t.Fatalf("outside the networks = %v", err)
	}
	if _, err := svc.CreateRefreshToken(session, SessionDevice{}); !errors.Is(err, ErrSignInNetwork) {
		t.Fatalf("an unknown address must be refused: %v", err)
	}
	token, err := svc.CreateRefreshToken(session, SessionDevice{ClientIP: "192.0.2.50"})
	if err != nil {
		t.Fatal(err)
	}
	// Refresh resolves the partner from the membership (11) and checks again.
	if _, err := svc.ValidateRefreshToken(token, SessionDevice{ClientIP: "198.51.100.1"}); !errors.Is(err, ErrInvalidRefreshToken) || !errors.Is(err, ErrSignInNetwork) {
		t.Fatalf("refresh outside the networks = %v", err)
	}
	if _, err := svc.ValidateRefreshToken(token, SessionDevice{ClientIP: "192.0.2.51"}); err != nil {
		t.Fatalf("refresh inside = %v", err)
	}
	// The session partner comes from the membership, not the caller.
	if _, err := svc.CreateRefreshToken(&model.UserSession{Id: 7}, SessionDevice{ClientIP: "198.51.100.1"}); !errors.Is(err, ErrSignInNetwork) {
		t.Fatalf("a session without a partner id = %v", err)
	}
	delete(store.networks, 11)
	if _, err := svc.CreateRefreshToken(session, SessionDevice{ClientIP: "198.51.100.1"}); err != nil {
		t.Fatalf("a partner without networks admits any address: %v", err)
	}
}

func TestNewDeviceNotice(t *testing.T) {
	withSessionConfig(t, true, false, 0)
	svc := newLocalUserService(t, memberStore())
	notifier := &recordingNotifier{}
	svc.SignInNotifier = notifier

	signIn(t, svc, deviceA)
	if len(notifier.notices) != 0 {
		t.Fatal("a first sign-in has no earlier device to compare with")
	}
	signIn(t, svc, deviceA)
	if len(notifier.notices) != 0 {
		t.Fatal("a known device is not news")
	}
	signIn(t, svc, deviceB)
	signIn(t, svc, "")
	if len(notifier.notices) != 2 || notifier.notices[0].DeviceSecret != deviceB || notifier.notices[0].ClientIP != "192.0.2.1" {
		t.Fatalf("notices = %+v", notifier.notices)
	}

	notifier.err = errors.New("mail down")
	if _, err := svc.CreateRefreshToken(&model.UserSession{Id: 7}, SessionDevice{DeviceSecret: "cccc"}); err != nil {
		t.Fatalf("a failed notice must not fail the sign-in: %v", err)
	}

	withSessionConfig(t, false, false, 0)
	signIn(t, svc, "dddd")
	if len(notifier.notices) != 3 {
		t.Fatal("notices are off")
	}
}

func TestNewDeviceLookupIsBestEffort(t *testing.T) {
	withSessionConfig(t, true, false, 0)
	store := memberStore()
	store.failQuery[qDeviceSeen] = errDatabaseDown
	if _, token := signIn(t, newLocalUserService(t, store), deviceA); token == "" {
		t.Fatal("no refresh token")
	}
}

func TestKnownDeviceAndStepUpCode(t *testing.T) {
	store := memberStore()
	svc := newLocalUserService(t, store)
	if err := svc.SendStepUpCode(7); !errors.Is(err, ErrStepUpUnavailable) {
		t.Fatalf("without a notifier = %v", err)
	}
	notifier := &recordingNotifier{}
	svc.SignInNotifier = notifier
	if err := svc.SendStepUpCode(7); err != nil || len(notifier.codes) != 1 || len(notifier.codes[0]) != 6 {
		t.Fatalf("step-up = %v, %v", err, notifier.codes)
	}
	if store.count(qGenerateOTP) != 1 {
		t.Fatal("the code must be stored for VerifyOTP")
	}

	signIn(t, svc, deviceA)
	for secret, want := range map[string]bool{deviceA: true, deviceB: false, "": false} {
		if known, err := svc.IsKnownDevice(7, secret); err != nil || known != want {
			t.Errorf("%q known = %v, %v", secret, known, err)
		}
	}
}

func TestMailSignInNotifier(t *testing.T) {
	mail := &capturedMail{}
	n := &MailSignInNotifier{Mail: mail, Brand: "Acme"}
	account := &model.UserSession{Email: "ada@example.com"}
	if err := n.NewDeviceSignIn(context.Background(), account, SessionDevice{UserAgent: "Firefox", ClientIP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if mail.subject != "Acme: New sign-in" || !strings.Contains(mail.body, "192.0.2.1") || !strings.Contains(mail.body, "Firefox") || mail.to[0] != "ada@example.com" {
		t.Fatalf("mail = %+v", mail)
	}
	if err := n.StepUpCode(context.Background(), account, "123456"); err != nil || !strings.Contains(mail.body, "123456") {
		t.Fatalf("code mail = %+v, %v", mail, err)
	}
	if err := n.StepUpCode(context.Background(), &model.UserSession{}, "1"); err == nil {
		t.Fatal("an account without email must fail")
	}
	for _, n := range []SignInNotifier{&MailSignInNotifier{}, (*MailSignInNotifier)(nil)} {
		if err := n.StepUpCode(context.Background(), account, "1"); !errors.Is(err, ErrStepUpUnavailable) {
			t.Fatalf("missing mail sender = %v", err)
		}
	}
}

type capturedMail struct {
	subject, body string
	to            []string
}

func (m *capturedMail) SendEmail(_ context.Context, subject, body string, to []string, _ map[string]string) error {
	m.subject, m.body, m.to = subject, body, to
	return nil
}

func TestReplaceSignInNetworks(t *testing.T) {
	store := newMemStore()
	svc := &SignInNetworkService{DB: memRepo{store: store}}
	ctx := context.Background()
	if err := svc.Replace(ctx, 11, "10.0.0.0/8", "192.0.2.1"); !errors.Is(err, ErrSignInNetworkLockout) {
		t.Fatalf("lockout = %v", err)
	}
	if err := svc.Replace(ctx, 11, "bogus", "192.0.2.1"); !errors.Is(err, common.ErrInvalidCIDRList) {
		t.Fatalf("bad list = %v", err)
	}
	if err := svc.Replace(ctx, 0, "", "192.0.2.1"); err == nil {
		t.Fatal("a partner is required")
	}
	if len(store.calls) != 0 {
		t.Fatalf("a refused list must not touch the table: %v", store.calls)
	}
	if err := svc.Replace(ctx, 11, "192.0.2.0/24, 192.0.2.7/24, 10.0.0.1", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(store.calls, ",") != "clear_signin_networks,add_signin_network,add_signin_network" || store.commits != 1 {
		t.Fatalf("calls = %v commits %d", store.calls, store.commits)
	}
	if err := svc.Replace(ctx, 11, "", "192.0.2.1"); err != nil {
		t.Fatalf("clearing = %v", err)
	}
}

func TestSessionIDRidesTheJWT(t *testing.T) {
	svc := newLocalUserService(t, memberStore())
	session, _ := signIn(t, svc, deviceA)
	session.ExpiresAt, session.IssuedAt = time.Now().Add(time.Minute).Unix(), time.Now().Unix()
	token, err := svc.CreateJWT(session)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := svc.ParseJWT(token)
	if err != nil || parsed.SessionID != session.SessionID {
		t.Fatalf("parsed = %+v, %v", parsed, err)
	}
}
