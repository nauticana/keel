package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/connect"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// nonceDB keeps auth_nonce rows in memory.
type nonceDB struct {
	port.DatabaseRepository
	rows map[string][2]string // nonce → purpose, payload
}

func (d *nonceDB) GetQueryService(context.Context, map[string]string) port.QueryService { return d }
func (d *nonceDB) GenID() int64                                                         { return 0 }
func (d *nonceDB) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	out := &model.QueryResult{}
	switch name {
	case "nonce_insert":
		d.rows[args[0].(string)] = [2]string{args[1].(string), args[2].(string)}
	case "nonce_consume":
		if row, ok := d.rows[args[0].(string)]; ok && row[0] == args[1].(string) {
			delete(d.rows, args[0].(string))
			out.Rows = [][]any{{row[1]}}
		}
	case "nonce_peek":
		if row, ok := d.rows[args[0].(string)]; ok && row[0] == args[1].(string) {
			out.Rows = [][]any{{row[1]}}
		}
	}
	return out, nil
}

type handoffSignIn struct {
	user.UserService
	twoFactor bool
	refuse    bool
	refreshed []string // sign-in methods of minted refresh tokens
	maxAge    time.Duration
}

func (u *handoffSignIn) GetUserById(id int) (*model.UserSession, error) {
	return &model.UserSession{Id: id, PartnerId: 40, TwoFactorEnabled: u.twoFactor}, nil
}
func (u *handoffSignIn) CheckSignInMethod(int, string) error {
	if u.refuse {
		return user.ErrSSORequired
	}
	return nil
}
func (u *handoffSignIn) CreateJWT(*model.UserSession) (string, error) { return "jwt", nil }
func (u *handoffSignIn) CreateRefreshToken(s *model.UserSession, _ user.SessionDevice) (string, error) {
	u.refreshed = append(u.refreshed, s.SignInMethod)
	u.maxAge = s.SessionMaxAge
	return "refresh", nil
}
func (u *handoffSignIn) CreateLoginToken(int, string) (string, error) { return "login-token", nil }

func newSignInHandoff(t *testing.T, users *handoffSignIn) *PublicHandler {
	t.Helper()
	nonces := &connect.NonceService{DB: &nonceDB{rows: map[string][2]string{}}}
	nonces.Init(context.Background())
	return &PublicHandler{AbstractHandler: AbstractHandler{UserService: users}, RegisterService: &user.RegistrationService{}, Handoff: nonces}
}

func exchange(h *PublicHandler, code string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.GetPublicRoutes()["/public/register/exchange"](rec, httptest.NewRequest(http.MethodPost, "/public/register/exchange", strings.NewReader(`{"code":"`+code+`"}`)))
	return rec
}

func TestHandoffCodeIsSingleUse(t *testing.T) {
	users := &handoffSignIn{}
	h := newSignInHandoff(t, users)
	code, err := h.HandoffCode(context.Background(), &model.UserSession{Id: 7, SignInMethod: user.SignInTenant})
	if err != nil {
		t.Fatal(err)
	}
	rec := exchange(h, code)
	var envelope struct{ Data map[string]any }
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	body := envelope.Data
	if body["refreshToken"] != "refresh" || body["partnerId"] != float64(40) || len(users.refreshed) != 1 || users.refreshed[0] != user.SignInTenant {
		t.Fatalf("body %v refreshed %v", body, users.refreshed)
	}
	if rec := exchange(h, code); rec.Code != http.StatusBadRequest {
		t.Fatalf("a used code must be refused, got %d", rec.Code)
	}
	if _, err := h.HandoffCode(context.Background(), &model.UserSession{Id: 7}); err == nil {
		t.Fatal("a session without a sign-in method must not be handed off")
	}
}

func TestHandoffExchangeCapsSessionLifetime(t *testing.T) {
	users := &handoffSignIn{}
	h := newSignInHandoff(t, users)
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ExchangeHandoff(rec, httptest.NewRequest(http.MethodPost, "/public/register/exchange", strings.NewReader(body)))
		return rec
	}
	for _, days := range []string{"-1", "0", "3651"} {
		code, _ := h.HandoffCode(context.Background(), &model.UserSession{Id: 7, SignInMethod: user.SignInTenant})
		if rec := post(`{"code":"` + code + `","sessionMaxDays":` + days + `}`); rec.Code != http.StatusBadRequest || len(users.refreshed) != 0 {
			t.Fatalf("sessionMaxDays %s: %d %s", days, rec.Code, rec.Body.String())
		}
	}
	code, _ := h.HandoffCode(context.Background(), &model.UserSession{Id: 7, SignInMethod: user.SignInTenant})
	if rec := post(`{"code":"` + code + `","sessionMaxDays":30}`); rec.Code != http.StatusOK || users.maxAge != 30*24*time.Hour {
		t.Fatalf("status %d maxAge %v", rec.Code, users.maxAge)
	}
}

func TestHandoffExchangeKeepsSignInChecks(t *testing.T) {
	users := &handoffSignIn{twoFactor: true}
	h := newSignInHandoff(t, users)
	code, _ := h.HandoffCode(context.Background(), &model.UserSession{Id: 8, SignInMethod: user.SignInExternal})
	rec := exchange(h, code)
	if !strings.Contains(rec.Body.String(), `"twoFactorRequired":true`) || len(users.refreshed) != 0 {
		t.Fatalf("2FA account: %d %s", rec.Code, rec.Body.String())
	}

	users.twoFactor, users.refuse = false, true
	code, _ = h.HandoffCode(context.Background(), &model.UserSession{Id: 8, SignInMethod: user.SignInExternal})
	if rec := exchange(h, code); rec.Code != http.StatusForbidden || len(users.refreshed) != 0 {
		t.Fatalf("SSO refusal: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRegistrationRoutes(t *testing.T) {
	h := newSignInHandoff(t, &handoffSignIn{})
	if _, ok := h.GetAuthRoutes("/api/v1")["/api/v1/register/partner"]; !ok {
		t.Fatal("partner setup route missing")
	}
	if len((&PublicHandler{}).GetAuthRoutes("/api/v1")) != 0 {
		t.Fatal("partner setup mounted without RegisterService")
	}
	if _, ok := (&PublicHandler{RegisterService: &user.RegistrationService{}}).GetPublicRoutes()["/public/register/exchange"]; ok {
		t.Fatal("exchange mounted without Handoff")
	}

	rec := httptest.NewRecorder()
	h.ConfirmRegistration(rec, httptest.NewRequest(http.MethodGet, "/public/register/confirm?email=a@b.c&code=1", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("confirm mints tokens and must be POST, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ConfirmRegistration(rec, httptest.NewRequest(http.MethodPost, "/public/register/confirm?email=a@b.c&code=12345678901234567890", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an overlong code must be refused, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.CreatePartner(rec, httptest.NewRequest(http.MethodPost, "/api/v1/register/partner", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("partner setup without a session = %d", rec.Code)
	}
}

func TestCheckoutFailureKeepsRegistration(t *testing.T) {
	journal := &recordingJournal{}
	h := &PublicHandler{AbstractHandler: AbstractHandler{Journal: journal}}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/register/partner", nil)
	rec := httptest.NewRecorder()
	if !h.checkoutTolerated(rec, r, fmt.Errorf("%w: provider down", user.ErrCheckout)) || len(journal.errors) != 1 || rec.Body.Len() != 0 {
		t.Fatalf("a checkout failure must be logged, not answered: %v %s", journal.errors, rec.Body.String())
	}
	if h.checkoutTolerated(rec, r, user.ErrAlreadyMember) || rec.Code != http.StatusConflict {
		t.Fatalf("ErrAlreadyMember = %d", rec.Code)
	}
	if !errors.Is(fmt.Errorf("wrapped: %w", user.ErrCheckout), user.ErrCheckout) {
		t.Fatal("ErrCheckout must survive wrapping")
	}
}

type twoFactorUsers struct {
	handoffSignIn
	trusted bool
}

func (u *twoFactorUsers) GetUserByLogin(string, string) (*model.UserSession, error) {
	return &model.UserSession{Id: 5, TwoFactorEnabled: true}, nil
}
func (u *twoFactorUsers) IsTrustedDevice(int, string) (bool, error) { return u.trusted, nil }
func (u *twoFactorUsers) GetUserMenu(int) ([]model.UserMenu, error) { return nil, nil }

// Password login must stop at the 2FA step unless the device is trusted.
func TestPasswordLoginRequiresSecondFactor(t *testing.T) {
	users := &twoFactorUsers{}
	h := &PublicHandler{AbstractHandler: AbstractHandler{UserService: users}}
	login := func(cookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/public/login/local", strings.NewReader(`{"username":"u","password":"p"}`))
		if cookie {
			r.AddCookie(&http.Cookie{Name: DefaultTrustedDeviceCookie.Name, Value: "secret"})
		}
		rec := httptest.NewRecorder()
		h.LoginLocal(rec, r)
		return rec
	}
	for name, cookie := range map[string]bool{"no cookie": false, "unknown device": true} {
		rec := login(cookie)
		if !strings.Contains(rec.Body.String(), `"loginToken":"login-token"`) || len(users.refreshed) != 0 {
			t.Fatalf("%s: tokens minted without the second factor: %s", name, rec.Body.String())
		}
	}
	users.trusted = true
	if rec := login(true); !strings.Contains(rec.Body.String(), `"twoFactorRequired":false`) || len(users.refreshed) != 1 {
		t.Fatalf("trusted device: %s", rec.Body.String())
	}
}
