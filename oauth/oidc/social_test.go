package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/crypto"
)

func socialVerifier(idp *fakeIdP) *SocialVerifier {
	keys := crypto.NewJWKSProvider(idp.srv.URL+"/jwks", time.Hour, idp.srv.Client())
	return &SocialVerifier{GoogleKeys: keys, AppleKeys: keys}
}

func socialToken(idp *fakeIdP, iss, aud string) string {
	return idp.signRSA(jwt.MapClaims{"iss": iss, "aud": aud, "sub": "s-1", "exp": time.Now().Add(time.Hour).Unix(),
		"nonce": "n-1", "email": "a@acme.example", "email_verified": "true", "given_name": "Ada", "hd": "acme.example"})
}

func TestSocialVerifierAcceptsBothGoogleIssuerForms(t *testing.T) {
	withConfig(t, "google-client", "apple-client")
	idp := newFakeIdP(t)
	v := socialVerifier(idp)
	for _, iss := range []string{GoogleIssuer, "accounts.google.com"} {
		a, nonce, err := v.Verify(context.Background(), ProviderGoogle, socialToken(idp, iss, "google-client"))
		if err != nil || a.Issuer != GoogleIssuer || a.Subject != "s-1" || !a.EmailVerified || a.HostedDomain != "acme.example" || nonce != "n-1" {
			t.Fatalf("%s: %+v %q %v", iss, a, nonce, err)
		}
	}
	a, _, err := v.Verify(context.Background(), ProviderApple, socialToken(idp, AppleIssuer, "apple-client"))
	if err != nil || a.Issuer != AppleIssuer {
		t.Fatalf("apple: %+v %v", a, err)
	}
}

func TestSocialVerifierRefusals(t *testing.T) {
	withConfig(t, "google-client", "apple-client")
	idp := newFakeIdP(t)
	v := socialVerifier(idp)
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"google audience": func() error {
			_, _, err := v.Verify(ctx, ProviderGoogle, socialToken(idp, GoogleIssuer, "apple-client"))
			return err
		},
		"google issuer": func() error {
			_, _, err := v.Verify(ctx, ProviderGoogle, socialToken(idp, AppleIssuer, "google-client"))
			return err
		},
		"apple issuer": func() error {
			_, _, err := v.Verify(ctx, ProviderApple, socialToken(idp, GoogleIssuer, "apple-client"))
			return err
		},
		"ES256": func() error {
			tok := idp.signWith(jwt.SigningMethodES256, "ec", idp.ecKey, jwt.MapClaims{"iss": GoogleIssuer, "aud": "google-client", "sub": "s", "exp": time.Now().Add(time.Hour).Unix()})
			_, _, err := v.Verify(ctx, ProviderGoogle, tok)
			return err
		},
	} {
		if err := call(); err == nil || errors.Is(err, ErrProviderDisabled) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, provider := range []string{"facebook", ""} {
		if _, _, err := v.Verify(ctx, provider, "t"); !errors.Is(err, ErrProviderDisabled) {
			t.Errorf("%q: %v", provider, err)
		}
	}
	withConfig(t, "", "")
	for _, provider := range []string{ProviderGoogle, ProviderApple} {
		if _, _, err := v.Verify(ctx, provider, "t"); !errors.Is(err, ErrProviderDisabled) {
			t.Errorf("%s without a client id: %v", provider, err)
		}
	}
}

func TestGoogleCodeIdentity(t *testing.T) {
	withConfig(t, "", "")
	var tokenStatus = http.StatusOK
	var tokenBody, userInfo string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			if r.PostForm.Get("client_secret") != "sec" || r.PostForm.Get("code") != "c" || r.PostForm.Get("redirect_uri") != "postmessage" {
				t.Errorf("token form = %v", r.PostForm)
			}
			w.WriteHeader(tokenStatus)
			_, _ = w.Write([]byte(tokenBody))
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer at" {
				t.Errorf("userinfo auth = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(userInfo))
		case "/elsewhere":
			t.Error("the token request must not follow a redirect")
		}
	}))
	defer srv.Close()
	g := &GoogleCode{TokenURL: srv.URL + "/token", UserInfoURL: srv.URL + "/userinfo", HTTP: srv.Client()}
	ctx := context.Background()

	tokenBody, userInfo = `{"access_token":"at"}`, `{"id":"g-1","email":"a@acme.example","verified_email":true,"given_name":"Ada","hd":"acme.example"}`
	a, err := g.Identity(ctx, "cid", "sec", "c", "postmessage")
	if err != nil || a.Issuer != GoogleIssuer || a.Subject != "g-1" || a.HostedDomain != "acme.example" || !a.EmailVerified {
		t.Fatalf("Identity = %+v, %v", a, err)
	}

	tokenStatus, tokenBody = http.StatusBadRequest, `{"error":"invalid_grant","error_description":"Bad Request"}`
	var te *TokenError
	if _, err := g.Identity(ctx, "cid", "sec", "c", "postmessage"); !errors.As(err, &te) || te.Error() != "token exchange failed: invalid_grant — Bad Request" {
		t.Fatalf("refused code: %v", err)
	}
	tokenStatus, tokenBody = http.StatusOK, `{}`
	if _, err := g.Identity(ctx, "cid", "sec", "c", "postmessage"); !errors.As(err, &te) || te.Error() != "token exchange failed" {
		t.Fatalf("no access token: %v", err)
	}
	tokenBody, userInfo = `{"access_token":"at"}`, `{"id":"g-1","verified_email":false}`
	if _, err := g.Identity(ctx, "cid", "sec", "c", "postmessage"); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("unverified email: %v", err)
	}
	if _, err := g.Identity(ctx, "", "sec", "c", "postmessage"); !errors.Is(err, ErrProviderDisabled) {
		t.Fatalf("no client id: %v", err)
	}
	tokenStatus, tokenBody = http.StatusFound, ""
	redirecting := &GoogleCode{TokenURL: srv.URL + "/token", UserInfoURL: srv.URL + "/userinfo", HTTP: srv.Client()}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		t.Error("the token request must not follow a redirect")
	})
	if _, err := redirecting.Identity(ctx, "cid", "sec", "c", "postmessage"); err == nil {
		t.Fatal("a redirected token request must fail")
	}
}
