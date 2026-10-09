package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

type reauthUsers struct {
	user.UserService
	ssoOnly  bool
	code     string
	purpose  string
	email    string
	phone    string
	verified []string
	deleted  bool
}

func (u *reauthUsers) VerifyPasswordByID(_ int, password string) (bool, error) {
	return password == "right", nil
}

func (u *reauthUsers) Verify2FA(_ int, code string) (bool, error) { return code == "123456", nil }

func (u *reauthUsers) CheckSignInMethod(int, string) error {
	if u.ssoOnly {
		return user.ErrSSORequired
	}
	return nil
}

func (u *reauthUsers) GenerateOTP(_ int, purpose string) (string, error) {
	u.code, u.purpose = "654321", purpose
	return u.code, nil
}

func (u *reauthUsers) VerifyOTP(_ int, purpose, code string) error {
	u.verified = append(u.verified, purpose)
	if purpose != u.purpose || code != u.code || code == "" {
		return errors.New("invalid OTP")
	}
	u.code = ""
	return nil
}

func (u *reauthUsers) GetUserById(id int) (*model.UserSession, error) {
	return &model.UserSession{Id: id, Email: u.email, PhoneNumber: u.phone}, nil
}

func (u *reauthUsers) DeleteAccount(int, string) error {
	u.deleted = true
	return nil
}

type countingCache struct {
	cache.CacheService
	n int64
}

func (c *countingCache) IncrementWithTTL(context.Context, string, time.Duration) (int64, error) {
	c.n++
	return c.n, nil
}

type sentNotifications struct{ channels []string }

func (s *sentNotifications) Send(_ context.Context, req port.NotificationRequest) error {
	s.channels = append(s.channels, req.Channel)
	return nil
}

func deleteAccount(h *SecurityHandler, body string) int {
	r := httptest.NewRequest(http.MethodDelete, "/api/user/account", strings.NewReader(body))
	stashSession(r, &model.UserSession{Id: 3})
	w := httptest.NewRecorder()
	h.DeleteAccount(w, r)
	return w.Code
}

func sendReauth(h *OTPHandler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/user/reauth/send", strings.NewReader(body))
	stashSession(r, &model.UserSession{Id: 3})
	w := httptest.NewRecorder()
	h.SendReauthOTP(w, r)
	return w
}

func TestOTPAuthRoutesExposeReauthenticationSend(t *testing.T) {
	routes := (&OTPHandler{}).GetAuthRoutes()
	if len(routes) != 1 || routes[common.RestPrefix+"/user/reauth/send"] == nil {
		t.Fatalf("routes = %v", routes)
	}
}

func TestRecentAuthAcceptsEachProof(t *testing.T) {
	for body, want := range map[string]int{
		`{}`:                                    http.StatusUnauthorized,
		`{"password":"wrong"}`:                  http.StatusUnauthorized,
		`{"password":"right"}`:                  http.StatusNoContent,
		`{"twoFactorCode":"000000"}`:            http.StatusUnauthorized,
		`{"twoFactorCode":"123456"}`:            http.StatusNoContent,
		`{"reauthCode":"654321"}`:               http.StatusUnauthorized, // never sent
		`{"password":"wrong","reauthCode":"x"}`: http.StatusUnauthorized,
	} {
		users := &reauthUsers{}
		if got := deleteAccount(&SecurityHandler{AbstractHandler: AbstractHandler{UserService: users}}, body); got != want || users.deleted != (want == http.StatusNoContent) {
			t.Errorf("%s = %d deleted=%v, want %d", body, got, users.deleted, want)
		}
	}
}

func TestReauthCodeDeletesAccountWithoutPasswordOr2FA(t *testing.T) {
	users := &reauthUsers{email: "a@acme.com"}
	notes := &sentNotifications{}
	otp := &OTPHandler{AbstractHandler: AbstractHandler{UserService: users}, Cache: &countingCache{}, NotificationSvc: notes}
	if w := sendReauth(otp, `{}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"channel":"email"`) {
		t.Fatalf("send = %d %s", w.Code, w.Body.String())
	}
	if users.purpose != user.OTPPurposeReauth || len(notes.channels) != 1 {
		t.Fatalf("purpose %q, sends %v", users.purpose, notes.channels)
	}
	sec := &SecurityHandler{AbstractHandler: AbstractHandler{UserService: users}}
	if got := deleteAccount(sec, `{"reauthCode":"000000"}`); got != http.StatusUnauthorized || users.deleted {
		t.Fatalf("wrong code = %d deleted=%v", got, users.deleted)
	}
	if got := deleteAccount(sec, `{"reauthCode":"654321"}`); got != http.StatusNoContent || !users.deleted {
		t.Fatalf("right code = %d deleted=%v", got, users.deleted)
	}
	users.deleted = false
	if got := deleteAccount(sec, `{"reauthCode":"654321"}`); got != http.StatusUnauthorized || users.deleted {
		t.Fatal("a re-authentication code must be single-use")
	}
}

func TestReauthCodeRefusedWhereSSOIsRequired(t *testing.T) {
	users := &reauthUsers{email: "a@acme.com", ssoOnly: true}
	otp := &OTPHandler{AbstractHandler: AbstractHandler{UserService: users}, Cache: &countingCache{}}
	if w := sendReauth(otp, `{}`); w.Code != http.StatusForbidden || users.code != "" {
		t.Fatalf("send under SSO = %d, code generated %q", w.Code, users.code)
	}
	users.purpose, users.code = user.OTPPurposeReauth, "654321"
	sec := &SecurityHandler{AbstractHandler: AbstractHandler{UserService: users}}
	if got := deleteAccount(sec, `{"reauthCode":"654321"}`); got != http.StatusForbidden || users.deleted || len(users.verified) != 0 {
		t.Fatalf("code under SSO = %d deleted=%v verified=%v", got, users.deleted, users.verified)
	}
}

func TestSendReauthOTPChannel(t *testing.T) {
	cases := []struct {
		email, phone, body string
		want               int
		sent               string
	}{
		{"", "+15550001111", `{}`, http.StatusOK, "sms"},
		{"a@acme.com", "+15550001111", `{"channel":"phone"}`, http.StatusOK, "sms"},
		{"a@acme.com", "", `{"channel":"phone"}`, http.StatusBadRequest, ""},
		{"a@acme.com", "", `{"channel":"fax"}`, http.StatusBadRequest, ""},
	}
	for _, c := range cases {
		users := &reauthUsers{email: c.email, phone: c.phone}
		notes := &sentNotifications{}
		otp := &OTPHandler{AbstractHandler: AbstractHandler{UserService: users}, Cache: &countingCache{}, NotificationSvc: notes}
		w := sendReauth(otp, c.body)
		if w.Code != c.want || strings.Join(notes.channels, ",") != c.sent {
			t.Errorf("%+v = %d sends %v", c, w.Code, notes.channels)
		}
	}
	if w := sendReauth(&OTPHandler{AbstractHandler: AbstractHandler{UserService: &reauthUsers{email: "a@acme.com"}}}, `{}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no cache = %d, want 503", w.Code)
	}
}
