package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

type sessionUsers struct {
	user.UserService
	known      bool
	codesSent  int
	verified   []string
	refreshed  int
	network    error
	revoked    []int64
	sessionsOf int
}

func (u *sessionUsers) GetUserByLogin(string, string) (*model.UserSession, error) {
	return &model.UserSession{Id: 5, Email: "a@b"}, nil
}
func (u *sessionUsers) GetUserById(id int) (*model.UserSession, error) {
	return &model.UserSession{Id: id, Email: "a@b"}, nil
}
func (u *sessionUsers) CheckSignInMethod(int, string) error          { return nil }
func (u *sessionUsers) IsKnownDevice(int, string) (bool, error)      { return u.known, nil }
func (u *sessionUsers) CreateLoginToken(int, string) (string, error) { return "login-token", nil }
func (u *sessionUsers) ValidateLoginToken(string) (int, string, error) {
	return 5, user.SignInPassword, nil
}
func (u *sessionUsers) SendStepUpCode(int) error                     { u.codesSent++; return nil }
func (u *sessionUsers) GetUserMenu(int) ([]model.UserMenu, error)    { return nil, nil }
func (u *sessionUsers) CreateJWT(*model.UserSession) (string, error) { return "jwt", nil }
func (u *sessionUsers) Verify2FA(int, string) (bool, error)          { return false, errors.New("no TOTP") }
func (u *sessionUsers) ParseJWT(string) (*model.UserSession, error) {
	return &model.UserSession{Id: 5, SessionID: 22}, nil
}
func (u *sessionUsers) CreateRefreshToken(*model.UserSession, user.SessionDevice) (string, error) {
	if u.network != nil {
		return "", u.network
	}
	u.refreshed++
	return "refresh", nil
}
func (u *sessionUsers) VerifyOTP(_ int, purpose, code string) error {
	u.verified = append(u.verified, purpose)
	if code != "123456" {
		return errors.New("wrong code")
	}
	return nil
}
func (u *sessionUsers) Sessions(userID int) ([]user.ActiveSession, error) {
	u.sessionsOf = userID
	return []user.ActiveSession{{ID: 21}, {ID: 22}}, nil
}
func (u *sessionUsers) RevokeSession(userID int, id int64) error {
	if id != 21 {
		return user.ErrSessionNotFound
	}
	u.revoked = append(u.revoked, id)
	return nil
}

func withStepUp(t *testing.T) {
	t.Helper()
	previous := config.Config()
	next := *previous
	next.StepUpNewDevice = true
	config.SetConfig(&next)
	t.Cleanup(func() { config.SetConfig(previous) })
}

func passwordLogin(h *PublicHandler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.LoginLocal(rec, httptest.NewRequest(http.MethodPost, "/public/login/local", strings.NewReader(`{"username":"u","password":"p"}`)))
	return rec
}

func TestNewDeviceStepUp(t *testing.T) {
	users := &sessionUsers{}
	h := &PublicHandler{AbstractHandler: AbstractHandler{UserService: users}}
	if rec := passwordLogin(h); users.refreshed != 1 || !strings.Contains(rec.Body.String(), `"twoFactorRequired":false`) {
		t.Fatalf("step-up off: %s", rec.Body.String())
	}

	withStepUp(t)
	rec := passwordLogin(h)
	if users.refreshed != 1 || users.codesSent != 1 || !strings.Contains(rec.Body.String(), `"twoFactorMethod":"email"`) || !strings.Contains(rec.Body.String(), `"loginToken":"login-token"`) {
		t.Fatalf("new device: %s", rec.Body.String())
	}
	users.known = true
	if passwordLogin(h); users.refreshed != 2 || users.codesSent != 1 {
		t.Fatal("a known device signs in without a code")
	}

	sec := &SecurityHandler{AbstractHandler: AbstractHandler{UserService: users}}
	verify := func(code string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		sec.Verify2FA(rec, httptest.NewRequest(http.MethodPost, "/public/2fa/verify", strings.NewReader(`{"loginToken":"login-token","code":"`+code+`"}`)))
		return rec
	}
	if rec := verify("000000"); rec.Code != http.StatusUnauthorized || users.refreshed != 2 {
		t.Fatalf("wrong code: %d", rec.Code)
	}
	if rec := verify("123456"); rec.Code != http.StatusOK || users.refreshed != 3 || users.verified[1] != user.OTPPurposeStepUp {
		t.Fatalf("step-up verify: %d %s %v", rec.Code, rec.Body.String(), users.verified)
	}
}

func TestStepUpUnavailableFailsClosed(t *testing.T) {
	withStepUp(t)
	users := &stepUpless{sessionUsers: sessionUsers{}}
	rec := passwordLogin(&PublicHandler{AbstractHandler: AbstractHandler{UserService: users}})
	if rec.Code != http.StatusServiceUnavailable || users.refreshed != 0 {
		t.Fatalf("no way to send a code: %d %s", rec.Code, rec.Body.String())
	}
}

type stepUpless struct{ sessionUsers }

func (*stepUpless) SendStepUpCode(int) error { return user.ErrStepUpUnavailable }

func TestSignInOutsideNetworksIsForbidden(t *testing.T) {
	users := &sessionUsers{network: user.ErrSignInNetwork}
	rec := passwordLogin(&PublicHandler{AbstractHandler: AbstractHandler{UserService: users}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "signin_network") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestListAndRevokeSessions(t *testing.T) {
	users := &sessionUsers{}
	h := &SecurityHandler{AbstractHandler: AbstractHandler{UserService: users}}
	routes := h.GetAuthRoutes()
	authed := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer t")
		rec := httptest.NewRecorder()
		routes[path](rec, req)
		return rec
	}
	rec := authed(http.MethodGet, "/api/user/sessions", "")
	var out struct {
		Data []user.ActiveSession `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK || len(out.Data) != 2 || out.Data[0].Current || !out.Data[1].Current || users.sessionsOf != 5 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	if rec := authed(http.MethodPost, "/api/user/sessions/revoke", `{"id":21}`); rec.Code != http.StatusNoContent || len(users.revoked) != 1 {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}
	if rec := authed(http.MethodPost, "/api/user/sessions/revoke", `{"id":99}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown session = %d", rec.Code)
	}
}
