package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/oidc"
	"github.com/nauticana/keel/port"
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

func TestSocialIdentityMapsOnlyGoogleProfileClaims(t *testing.T) {
	a := &port.IdentityAssertion{Issuer: oidc.GoogleIssuer, Subject: "1", Email: "a@acme.com", EmailVerified: true,
		GivenName: "Ada", FamilyName: "L", HostedDomain: "acme.com"}
	id := socialIdentity("google", a)
	if id != (user.ExternalIdentity{Provider: "google", Issuer: user.GoogleIssuer, Subject: "1", Email: "a@acme.com",
		EmailVerified: true, FirstName: "Ada", LastName: "L", HostedDomain: "acme.com"}) {
		t.Fatalf("google identity = %+v", id)
	}
	a.Issuer = oidc.AppleIssuer
	if id := socialIdentity("apple", a); id.FirstName != "" || id.HostedDomain != "" || id.Issuer != user.AppleIssuer {
		t.Fatalf("apple identity = %+v", id)
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
