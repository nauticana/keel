package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/port"
)

const testRedirect = "https://app.example/sso/callback"

var secretPost = ClientCredential{Method: AuthSecretPost, Secret: "s3cret"}

// begin runs Begin and returns the authorization request and pending state.
func begin(t *testing.T, c *Client, scopes ...string) (url.Values, pending, string) {
	t.Helper()
	r, err := c.Begin(context.Background(), port.IdentityBegin{State: "st-1", RedirectURI: testRedirect, LoginHint: "ada@acme.example", Scopes: scopes})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatal(err)
	}
	var p pending
	if err := json.Unmarshal([]byte(r.Pending), &p); err != nil {
		t.Fatal(err)
	}
	return u.Query(), p, r.Pending
}

func complete(c *Client, pendingJSON string, params url.Values) (*port.IdentityAssertion, error) {
	return c.Complete(context.Background(), port.IdentityCallback{RedirectURI: testRedirect, Params: params, Pending: pendingJSON})
}

func callback(state string) url.Values { return url.Values{"state": {state}, "code": {"code-1"}} }

func TestCodeFlowSignsIn(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	c := idp.client(secretPost)
	q, p, pend := begin(t, c)
	for k, want := range map[string]string{
		"response_type": "code", "client_id": "client-1", "redirect_uri": testRedirect, "state": "st-1",
		"code_challenge_method": "S256", "login_hint": "ada@acme.example", "scope": "openid email profile",
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Get("nonce") != p.Nonce || p.Nonce == "" {
		t.Fatalf("nonce %q / %q", q.Get("nonce"), p.Nonce)
	}
	idp.claims = idp.baseClaims("client-1", p.Nonce)

	a, err := complete(c, pend, callback("st-1"))
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if a.Issuer != idp.srv.URL || a.Subject != "user-1" || a.Email != "ada@acme.example" || !a.EmailVerified ||
		a.GivenName != "Ada" || a.FamilyName != "Lovelace" || !slices.Equal(a.AuthMethods, []string{"pwd", "mfa"}) ||
		!slices.Equal(a.Claims["groups"], []string{"g1", "g2"}) || a.AccessToken != "" {
		t.Fatalf("assertion = %+v", a)
	}
	if _, ok := a.Claims["nonce"]; ok {
		t.Fatal("protocol claims must not reach role mapping")
	}
	sum := sha256.Sum256([]byte(idp.lastReq.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
		t.Fatal("the token request must carry the PKCE verifier of the challenge")
	}
	if idp.lastReq.Get("client_secret") != "s3cret" || idp.lastReq.Get("redirect_uri") != testRedirect || idp.lastReq.Get("code") != "code-1" {
		t.Fatalf("token request = %v", idp.lastReq)
	}
}

func TestCodeFlowReturnsAccessTokenOnlyForExtraScopes(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	c := idp.client(secretPost)
	q, p, pend := begin(t, c, "Domain.Read.All")
	if !strings.HasSuffix(q.Get("scope"), " Domain.Read.All") {
		t.Fatalf("scope = %q", q.Get("scope"))
	}
	idp.claims = idp.baseClaims("client-1", p.Nonce)
	a, err := complete(c, pend, callback("st-1"))
	if err != nil || a.AccessToken != "at" {
		t.Fatalf("assertion = %+v, %v", a, err)
	}
}

func TestCodeFlowRejectsOversizedTokenResponse(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	c := idp.client(secretPost)
	_, p, pend := begin(t, c)
	idp.claims = idp.baseClaims("client-1", p.Nonce)
	saved := config.Config().OutboundMaxResponseSize
	config.Config().OutboundMaxResponseSize = 16
	t.Cleanup(func() { config.Config().OutboundMaxResponseSize = saved })
	if _, err := complete(c, pend, callback("st-1")); !errors.Is(err, common.ErrResponseTooLarge) {
		t.Fatalf("oversized token response = %v", err)
	}
}

func TestCodeFlowRefusals(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	c := idp.client(secretPost)
	_, p, pend := begin(t, c)
	hmac := func(cl jwt.MapClaims) string { return idp.signWith(jwt.SigningMethodHS256, "rsa", []byte("k"), cl) }
	es256 := func(cl jwt.MapClaims) string { return idp.signWith(jwt.SigningMethodES256, "ec", idp.ecKey, cl) }

	cases := map[string]struct {
		edit   func(jwt.MapClaims)
		sign   func(jwt.MapClaims) string
		params url.Values
		status int
		body   string
		check  func(error) bool
	}{
		"state mismatch":     {params: callback("other")},
		"idp error":          {params: url.Values{"state": {"st-1"}, "error": {"access_denied"}}, check: func(err error) bool { var ce *CallbackError; return errors.As(err, &ce) && ce.Code == "access_denied" }},
		"no code":            {params: url.Values{"state": {"st-1"}}},
		"nonce mismatch":     {edit: func(cl jwt.MapClaims) { cl["nonce"] = "other" }},
		"no nonce":           {edit: func(cl jwt.MapClaims) { delete(cl, "nonce") }},
		"wrong audience":     {edit: func(cl jwt.MapClaims) { cl["aud"] = "client-2" }},
		"several audiences":  {edit: func(cl jwt.MapClaims) { cl["aud"] = []any{"client-1", "client-2"} }},
		"wrong issuer":       {edit: func(cl jwt.MapClaims) { cl["iss"] = "https://evil.example" }},
		"expired":            {edit: func(cl jwt.MapClaims) { cl["exp"] = time.Now().Add(-time.Hour).Unix() }},
		"no subject":         {edit: func(cl jwt.MapClaims) { delete(cl, "sub") }},
		"symmetric":          {sign: hmac},
		"not advertised alg": {sign: es256},
		"refused code":       {status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`, check: func(err error) bool { var te *TokenError; return errors.As(err, &te) && te.Code == "invalid_grant" }},
		"no id_token":        {body: `{"access_token":"at"}`},
		"issuer outage":      {status: http.StatusBadGateway, check: func(err error) bool { return err != nil && !errors.Is(err, ErrInvalidResponse) }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cl := idp.baseClaims("client-1", p.Nonce)
			if tc.edit != nil {
				tc.edit(cl)
			}
			idp.claims, idp.sign, idp.status, idp.body = cl, idp.signRSA, http.StatusOK, tc.body
			if tc.sign != nil {
				idp.sign = tc.sign
			}
			if tc.status != 0 {
				idp.status = tc.status
			}
			params := tc.params
			if params == nil {
				params = callback("st-1")
			}
			a, err := complete(c, pend, params)
			check := tc.check
			if check == nil {
				check = func(err error) bool { return errors.Is(err, ErrInvalidResponse) }
			}
			if a != nil || !check(err) {
				t.Fatalf("Complete = %+v, %v", a, err)
			}
		})
	}
}

func TestAudienceAndAuthorizedParty(t *testing.T) {
	withConfig(t, "", "")
	for name, tc := range map[string]struct {
		aud any
		azp any
		ok  bool
	}{
		"sole audience":                 {aud: "client-1", ok: true},
		"sole audience, azp the client": {aud: []any{"client-1"}, azp: "client-1", ok: true},
		"azp another client":            {aud: "client-1", azp: "client-2"},
		"azp not a string":              {aud: "client-1", azp: 7},
		"another audience, azp client":  {aud: []any{"client-1", "api"}, azp: "client-1"},
		"another audience, no azp":      {aud: []any{"client-1", "api"}},
		"client is not an audience":     {aud: []any{"api"}, azp: "client-1"},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIdP(t)
			c := idp.client(secretPost)
			_, p, pend := begin(t, c)
			idp.claims = idp.baseClaims("client-1", p.Nonce)
			idp.claims["aud"] = tc.aud
			if tc.azp != nil {
				idp.claims["azp"] = tc.azp
			}
			_, err := complete(c, pend, callback("st-1"))
			if tc.ok && err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Complete = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestECSignedTokenWhenAdvertised(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	idp.algs = []string{"ES256"}
	c := idp.client(secretPost)
	_, p, pend := begin(t, c)
	idp.claims = idp.baseClaims("client-1", p.Nonce)
	idp.sign = func(cl jwt.MapClaims) string { return idp.signWith(jwt.SigningMethodES256, "ec", idp.ecKey, cl) }
	if _, err := complete(c, pend, callback("st-1")); err != nil {
		t.Fatalf("ES256: %v", err)
	}
	idp.sign = idp.signRSA
	if _, err := complete(c, pend, callback("st-1")); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("RS256 when only ES256 is advertised: %v", err)
	}
}

func TestOverageClaimsAreReported(t *testing.T) {
	a, err := assertionFromClaims("iss", jwt.MapClaims{"sub": "s", "_claim_names": map[string]any{"groups": "src1"}, "hasgroups": true, "roles": "Admin"}, "", "")
	if err != nil || !slices.Contains(a.Overage, "groups") || !slices.Equal(a.Claims["roles"], []string{"Admin"}) {
		t.Fatalf("assertion = %+v, %v", a, err)
	}
	a, err = assertionFromClaims("iss", jwt.MapClaims{"sub": "s", "oid": "o-1", "upn": "ada@acme.example"}, "oid", "upn")
	if err != nil || a.Subject != "o-1" || a.Email != "ada@acme.example" || a.EmailVerified {
		t.Fatalf("custom claims = %+v, %v", a, err)
	}
}

func TestBeginRefusesUnsupportedClientAuth(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	idp.authMeth = []string{AuthSecretBasic}
	_, err := idp.client(secretPost).Begin(context.Background(), port.IdentityBegin{State: "s", RedirectURI: testRedirect})
	if !errors.Is(err, ErrBadConfiguration) {
		t.Fatalf("Begin = %v", err)
	}
	if _, err := idp.client(secretPost).Begin(context.Background(), port.IdentityBegin{RedirectURI: testRedirect}); !errors.Is(err, ErrBadConfiguration) {
		t.Fatalf("Begin without state = %v", err)
	}
}

func TestDiscoveryRefusals(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	ctx, url := context.Background(), idp.srv.URL+"/.well-known/openid-configuration"
	for name, issuer := range map[string]string{"other issuer": "https://other.example", "templated": "https://login.example/{tenantid}/v2.0", "empty": ""} {
		if _, err := FetchDiscovery(ctx, idp.srv.Client(), url, issuer); !errors.Is(err, ErrBadConfiguration) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := FetchDiscovery(ctx, idp.srv.Client(), strings.Replace(url, "https:", "http:", 1), idp.srv.URL); !errors.Is(err, ErrBadConfiguration) {
		t.Errorf("http discovery: %v", err)
	}
	idp.algs = nil
	if _, err := FetchDiscovery(ctx, idp.srv.Client(), url, idp.srv.URL); !errors.Is(err, ErrBadConfiguration) {
		t.Errorf("no algorithms: %v", err)
	}
	idp.algs, idp.issuer = []string{"RS256"}, "https://login.example/{tenantid}/v2.0"
	if _, err := FetchDiscovery(ctx, idp.srv.Client(), url, idp.srv.URL); !errors.Is(err, ErrBadConfiguration) {
		t.Errorf("templated document issuer: %v", err)
	}
}

func TestDefaultClientRefusesInternalIssuer(t *testing.T) {
	withConfig(t, "", "")
	idp := newFakeIdP(t)
	c := idp.client(secretPost)
	c.HTTP = nil
	if _, err := c.Begin(context.Background(), port.IdentityBegin{State: "s", RedirectURI: testRedirect}); err == nil {
		t.Fatal("a tenant issuer on an internal address must not be fetched")
	}
}
