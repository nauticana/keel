package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

type linkUsers struct {
	user.UserService
	linked int
}

func (u *linkUsers) VerifyPasswordByID(_ int, password string) (bool, error) {
	return password == "right", nil
}

func (u *linkUsers) Verify2FA(int, string) (bool, error) { return false, nil }

func (u *linkUsers) LinkExternalIdentity(int, user.ExternalIdentity) error {
	u.linked++
	return nil
}

func TestLinkSocialRequiresRecentAuthentication(t *testing.T) {
	users := &linkUsers{}
	h := &SocialLoginHandler{AbstractHandler: AbstractHandler{UserService: users}}
	for body, want := range map[string]int{
		`{"provider":"google","token":"t"}`:                         http.StatusUnauthorized,
		`{"provider":"google","token":"t","password":"wrong"}`:      http.StatusUnauthorized,
		`{"provider":"google","password":"right"}`:                  http.StatusBadRequest,
		`{"provider":"google","token":"forged","password":"right"}`: http.StatusUnauthorized,
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/user/social/link", strings.NewReader(body))
		stashSession(r, &model.UserSession{Id: 3})
		w := httptest.NewRecorder()
		h.LinkSocial(w, r)
		if w.Code != want {
			t.Errorf("%s = %d %s, want %d", body, w.Code, w.Body.String(), want)
		}
	}
	if users.linked != 0 {
		t.Fatal("no identity may be linked without re-authentication and a verified token")
	}
	w := httptest.NewRecorder()
	h.LinkSocial(w, httptest.NewRequest(http.MethodPost, "/api/v1/user/social/link", strings.NewReader(`{}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no session = %d", w.Code)
	}
}

func TestIdentityFromClaims(t *testing.T) {
	id := identityFromClaims("google", googleIssuer1, map[string]any{"sub": "1", "email": "a@acme.com", "email_verified": "true"})
	if id.Provider != "google" || id.Issuer != googleIssuer1 || id.Subject != "1" || id.Email != "a@acme.com" || !id.EmailVerified {
		t.Fatalf("identity = %+v", id)
	}
	if identityFromClaims("apple", appleIssuer, map[string]any{"email_verified": false}).EmailVerified {
		t.Fatal("email_verified false")
	}
}

func TestSocialSignInErrorKeepsOnlyActionableRefusals(t *testing.T) {
	for _, sentinel := range []error{user.ErrIdentityNotLinked, user.ErrIdentityLinked, user.ErrAccountUnavailable} {
		if got := socialSignInError(fmt.Errorf("wrapped: %w", sentinel)); got != sentinel {
			t.Errorf("%v mapped to %v", sentinel, got)
		}
	}
	if socialSignInError(errors.New("connection refused")) != nil {
		t.Fatal("internal errors must stay internal")
	}
}
