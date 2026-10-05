package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

type ssoUsers struct {
	user.UserService
	checked []string
	minted  int
}

func (u *ssoUsers) GetUserByLogin(string, string) (*model.UserSession, error) {
	return &model.UserSession{Id: 3}, nil
}
func (u *ssoUsers) GetUserById(int) (*model.UserSession, error) {
	return nil, errors.New("membership lookup failed")
}
func (u *ssoUsers) CheckSignInMethod(userID int, method string) error {
	u.checked = append(u.checked, method)
	if userID == 3 {
		return user.ErrSSORequired
	}
	return nil
}
func (u *ssoUsers) ValidateLoginToken(string) (int, string, error) {
	return 3, user.SignInPassword, nil
}
func (u *ssoUsers) CreateJWT(*model.UserSession) (string, error) { u.minted++; return "jwt", nil }

func TestPasswordLoginHonorsSSORequired(t *testing.T) {
	users := &ssoUsers{}
	h := &PublicHandler{AbstractHandler: AbstractHandler{UserService: users}}
	w := httptest.NewRecorder()
	h.LoginLocal(w, httptest.NewRequest(http.MethodPost, "/public/login/local", strings.NewReader(`{"username":"u","password":"p"}`)))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "sso_required") {
		t.Fatalf("status = %d %s", w.Code, w.Body.String())
	}
	if len(users.checked) != 1 || users.checked[0] != user.SignInPassword || users.minted != 0 {
		t.Fatalf("checked %v, minted %d", users.checked, users.minted)
	}
}

func TestSocialLoginRefusesDisabledProvider(t *testing.T) {
	h := &SocialLoginHandler{}
	for _, provider := range []string{"google", "apple", "facebook"} {
		w := httptest.NewRecorder()
		h.LoginSocial(w, httptest.NewRequest(http.MethodPost, "/public/login/social", strings.NewReader(`{"provider":"`+provider+`","token":"t"}`)))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "provider_not_enabled") {
			t.Errorf("%s without a client id = %d %s", provider, w.Code, w.Body.String())
		}
	}
}

// SSO turned on between the password step and the 2FA step still refuses.
func TestTwoFactorCompletionRechecksSSO(t *testing.T) {
	users := &ssoUsers{}
	h := &SecurityHandler{AbstractHandler: AbstractHandler{UserService: users}}
	for name, call := range map[string]func(http.ResponseWriter, *http.Request){"totp": h.Verify2FA, "backup code": h.VerifyBackupCode} {
		w := httptest.NewRecorder()
		call(w, httptest.NewRequest(http.MethodPost, "/public/2fa/verify", strings.NewReader(`{"loginToken":"3-12345678","code":"123456"}`)))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "sso_required") {
			t.Errorf("%s = %d %s", name, w.Code, w.Body.String())
		}
	}
	if users.minted != 0 {
		t.Fatal("no token may be minted")
	}
}
