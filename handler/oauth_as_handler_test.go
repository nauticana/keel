package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/oauth/authserver"
	"github.com/nauticana/keel/port"
)

func TestOAuthClientLimitIsServiceUnavailable(t *testing.T) {
	rec := httptest.NewRecorder()
	(&OAuthASHandler{}).writeOAuthError(rec, fmt.Errorf("register: %w", authserver.ErrOAuthClientLimit))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"error":"temporarily_unavailable"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

type registerClients struct{ port.OAuthClientStore }

func (registerClients) CreateClient(context.Context, *port.OAuthClient) error { return nil }

func TestOAuthRegisterPolicy(t *testing.T) {
	signer, err := authserver.NewEphemeralRS256Signer()
	if err != nil {
		t.Fatal(err)
	}
	journal := &recordingJournal{}
	h := &OAuthASHandler{Journal: journal, AS: authserver.NewLocal(signer, registerClients{}, nil, nil,
		authserver.Config{Issuer: "https://as.example", DefaultAudience: "https://rs.example", Scopes: []string{"read"}})}
	register := func(body string) (*httptest.ResponseRecorder, map[string]any) {
		rec := httptest.NewRecorder()
		h.register(rec, httptest.NewRequest(http.MethodPost, authserver.OAuthRegisterPath, strings.NewReader(body)))
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec, out
	}

	rec, out := register(`{"client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],
		"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_post"}`)
	if rec.Code != http.StatusCreated || out["client_secret"] == "" || out["token_endpoint_auth_method"] != "client_secret_post" ||
		out["client_secret_expires_at"] != float64(0) || out["client_id_issued_at"] == nil {
		t.Fatalf("confidential client: %d %s", rec.Code, rec.Body.String())
	}

	rec, out = register(`{"redirect_uris":["https://app.example/cb"],"grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_basic"}`)
	if rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" || !strings.Contains(fmt.Sprint(out["error_description"]), "grant_types") {
		t.Fatalf("machine grant: %d %s", rec.Code, rec.Body.String())
	}
	if len(journal.warnings) != 1 || !strings.Contains(journal.warnings[0], "grant_types") {
		t.Fatalf("refusal must be logged: %v", journal.warnings)
	}

	if rec, out = register(`{`); rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
		t.Fatalf("malformed body: %d %s", rec.Code, rec.Body.String())
	}
	if rec, out = register(`{"redirect_uris":["https://app.example/cb"]}{}`); rec.Code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
		t.Fatalf("trailing JSON: %d %s", rec.Code, rec.Body.String())
	}
}

func TestOAuthInvalidClientChallenges(t *testing.T) {
	rec := httptest.NewRecorder()
	(&OAuthASHandler{}).writeOAuthError(rec, authserver.ErrOAuthInvalidClient)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("status %d, challenge %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestAuthorizeRedirectCarriesIssuer(t *testing.T) {
	signer, err := authserver.NewEphemeralRS256Signer()
	if err != nil {
		t.Fatal(err)
	}
	h := &OAuthASHandler{AS: authserver.NewLocal(signer, registerClients{}, nil, nil, authserver.Config{Issuer: "https://as.example"})}
	rec := httptest.NewRecorder()
	h.redirectErr(rec, httptest.NewRequest(http.MethodGet, authserver.OAuthAuthorizePath, nil), "https://app.example/cb", "access_denied", "too many apps", "s")
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "iss=https%3A%2F%2Fas.example") || !strings.Contains(loc, "error_description=too+many+apps") {
		t.Fatalf("location = %q", loc)
	}
}

type authorizeClients struct{ port.OAuthClientStore }

func (authorizeClients) GetClient(_ context.Context, id string) (*port.OAuthClient, error) {
	if id != "c" {
		return nil, nil
	}
	return &port.OAuthClient{ClientID: "c", RedirectURIs: []string{"https://app.example/cb"}}, nil
}

func TestAuthorizeErrorsReturnToTheClient(t *testing.T) {
	signer, err := authserver.NewEphemeralRS256Signer()
	if err != nil {
		t.Fatal(err)
	}
	h := &OAuthASHandler{AS: authserver.NewLocal(signer, authorizeClients{}, nil, nil,
		authserver.Config{Issuer: "https://as.example", DefaultAudience: "https://rs.example", Scopes: []string{"read"}}),
		ResolveUser: func(*http.Request) *port.UserRef { return &port.UserRef{UserID: 1} }}
	const valid = "client_id=c&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=s&code_challenge=x&code_challenge_method=S256"
	authorize := func(query string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.authorize(rec, httptest.NewRequest(http.MethodGet, authserver.OAuthAuthorizePath+"?"+query, nil))
		return rec
	}
	for query, want := range map[string]string{
		"response_type=token&" + valid: "error=unsupported_response_type",
		"response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=s": "error=invalid_request",
		"response_type=code&scope=admin&" + valid:                                            "error=invalid_scope",
	} {
		rec := authorize(query)
		if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, "https://app.example/cb?") || !strings.Contains(loc, want) || !strings.Contains(loc, "state=s") {
			t.Fatalf("%s: %d %q", query, rec.Code, loc)
		}
	}
	for _, query := range []string{
		"response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&code_challenge=x&code_challenge_method=S256",
		"response_type=code&state=a&" + valid,
	} {
		if rec := authorize(query); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("%s must not redirect: %d", query, rec.Code)
		}
	}

	rec := authorize("response_type=code&" + valid)
	csp := rec.Header().Get("Content-Security-Policy")
	if rec.Code != http.StatusOK || !strings.Contains(csp, "form-action 'self' https://app.example") {
		t.Fatalf("consent page: %d csp %q", rec.Code, csp)
	}
}

func TestTokenRefusesRepeatedParameters(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, authserver.OAuthTokenPath, strings.NewReader("grant_type=a&grant_type=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	(&OAuthASHandler{}).token(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
