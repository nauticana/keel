package handler

import (
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/oauth/authserver"
	"github.com/nauticana/keel/port"
)

// OAuthASHandler is the HTTP bridge for the local OAuth 2.1 authorization
// server: it parses requests, authenticates the end user at /authorize via the
// injected ResolveUser, delegates all logic to the AuthorizationServer, and
// shapes responses. Mount it with backend.Handle(h.Routes()).
type OAuthASHandler struct {
	AS      port.AuthorizationServer
	Journal logger.ApplicationLogger

	// ResolveUser returns the logged-in user for /authorize, or nil if the
	// request carries no valid keel session. The app supplies this from its
	// own session mechanism (cookie/JWT).
	ResolveUser func(r *http.Request) *port.UserRef
	// LoginURL receives unauthenticated /authorize users with a ?return= back
	// to the authorize URL. Empty → 401 instead of redirecting.
	LoginURL string
	// Consent optionally overrides the built-in consent page.
	Consent func(w http.ResponseWriter, r *http.Request, c ConsentView)
	// CSRF optionally overrides the double-submit guard on the built-in consent
	// POST. Nil uses a default; ignored when Consent is set (a custom page owns
	// its own CSRF).
	CSRF *CSRF
}

func (h *OAuthASHandler) csrfGuard(r *http.Request) *CSRF {
	if h.CSRF != nil {
		return h.CSRF
	}
	// Auto: Secure on HTTPS (incl. behind a TLS-terminating proxy), relaxed on
	// plain-HTTP localhost dev so the consent cookie is actually sent.
	return &CSRF{
		CookieName: "keel_oauth_csrf",
		Path:       authserver.OAuthAuthorizePath,
		TTL:        10 * time.Minute,
		Insecure:   isLocalhostPlainHTTP(r),
	}
}

// isLocalhostPlainHTTP is true only for a non-TLS request to a loopback host —
// the single case where a Secure cookie can't be delivered and relaxing it is
// safe. Any non-loopback request keeps Secure, regardless of X-Forwarded-Proto,
// so a production HTTP misconfig fails loudly rather than silently downgrading.
func isLocalhostPlainHTTP(r *http.Request) bool {
	if r.TLS != nil {
		return false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// ConsentView is the data passed to the consent renderer.
type ConsentView struct {
	ClientName string
	Scopes     []string
	Action     string
	Fields     map[string]string
}

func (h *OAuthASHandler) Routes() map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		authserver.OAuthASMetadataPath: h.metadata,
		authserver.OAuthJWKSPath:       h.jwks,
		authserver.OAuthRegisterPath:   h.register,
		authserver.OAuthAuthorizePath:  h.authorize,
		authserver.OAuthTokenPath:      h.token,
		authserver.OAuthRevokePath:     h.revoke,
		authserver.OAuthIntrospectPath: h.introspect,
	}
}

func (h *OAuthASHandler) metadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.AS.Metadata())
}

func (h *OAuthASHandler) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, h.AS.JWKS())
}

func (h *OAuthASHandler) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		Scope                   string   `json:"scope"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		ClientName              string   `json:"client_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		h.writeOAuthError(w, authserver.ErrOAuthInvalidRequest)
		return
	}
	client, err := h.AS.Register(r.Context(), port.ClientRegistration{
		RedirectURIs:    body.RedirectURIs,
		GrantTypes:      body.GrantTypes,
		Scopes:          strings.Fields(body.Scope),
		TokenAuthMethod: body.TokenEndpointAuthMethod,
		Name:            body.ClientName,
	})
	if err != nil {
		h.writeOAuthError(w, err)
		return
	}
	resp := map[string]any{
		"client_id":                  client.ClientID,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                client.GrantTypes,
		"token_endpoint_auth_method": client.TokenAuthMethod,
		"client_name":                client.Name,
		"scope":                      strings.Join(client.Scopes, " "),
	}
	if client.Secret != "" {
		resp["client_secret"] = client.Secret
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *OAuthASHandler) authorize(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	get := func(k string) string { return strings.TrimSpace(r.Form.Get(k)) }
	if get("response_type") != "code" {
		http.Error(w, "unsupported response_type (only 'code')", http.StatusBadRequest)
		return
	}
	req := port.AuthorizeRequest{
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		Scopes:              strings.Fields(get("scope")),
		State:               get("state"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
		Resource:            get("resource"),
	}
	// Validate client + redirect BEFORE any redirect or consent (open-redirect
	// guard). scopes is the effective granted set the consent page must show.
	client, scopes, err := h.AS.ValidateAuthorizeRequest(r.Context(), req)
	if err != nil {
		http.Error(w, "invalid authorization request: "+err.Error(), http.StatusBadRequest)
		return
	}
	user := h.resolveUser(r)
	if user == nil {
		h.redirectToLogin(w, r)
		return
	}
	if r.Method != http.MethodPost {
		h.renderConsent(w, r, client, req, scopes)
		return
	}
	if h.Consent == nil && !h.csrfGuard(r).Validate(r, "csrf") {
		http.Error(w, `{"error":"invalid_csrf"}`, http.StatusForbidden)
		return
	}
	if get("approve") != "true" {
		h.redirectErr(w, r, req.RedirectURI, "access_denied", req.State)
		return
	}
	req.User = user
	req.ConsentGranted = true
	res, err := h.AS.Authorize(r.Context(), req)
	if err != nil {
		h.redirectErr(w, r, req.RedirectURI, err.Error(), req.State)
		return
	}
	u, _ := url.Parse(req.RedirectURI)
	q := u.Query()
	q.Set("code", res.Code)
	if res.State != "" {
		q.Set("state", res.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *OAuthASHandler) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeOAuthError(w, authserver.ErrOAuthInvalidRequest)
		return
	}
	_ = r.ParseForm()
	get := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	req := port.TokenRequest{
		GrantType:        get("grant_type"),
		Code:             get("code"),
		RedirectURI:      get("redirect_uri"),
		CodeVerifier:     get("code_verifier"),
		RefreshToken:     get("refresh_token"),
		Scopes:           strings.Fields(get("scope")),
		Resource:         get("resource"),
		Client:           extractClientAuth(r),
		SubjectToken:     get("subject_token"),
		SubjectTokenType: get("subject_token_type"),
	}
	resp, err := h.AS.Token(r.Context(), req)
	if err != nil {
		h.writeOAuthError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

func (h *OAuthASHandler) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { // RFC 7009: tokens must not ride a GET query string
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	// RFC 7009: 200 on success/no-op; 401 only when client auth fails.
	if err := h.AS.Revoke(r.Context(), strings.TrimSpace(r.PostForm.Get("token")),
		strings.TrimSpace(r.PostForm.Get("token_type_hint")), extractClientAuth(r)); err != nil {
		h.writeOAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *OAuthASHandler) introspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { // RFC 7662: tokens must not ride a GET query string
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	res, err := h.AS.Introspect(r.Context(), strings.TrimSpace(r.PostForm.Get("token")), extractClientAuth(r))
	if err != nil {
		h.writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *OAuthASHandler) resolveUser(r *http.Request) *port.UserRef {
	if h.ResolveUser == nil {
		return nil
	}
	return h.ResolveUser(r)
}

// The /authorize → login → /authorize bounce is bounded by
// --oauth_max_auth_redirects. Without it a misconfigured session (e.g. a
// localStorage bearer the browser never sends to /authorize) loops forever and
// can drain edge/CDN quota.
func (h *OAuthASHandler) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	if h.LoginURL == "" {
		http.Error(w, `{"error":"login required"}`, http.StatusUnauthorized)
		return
	}
	if n := authRetryCount(r); n >= *common.OAuthMaxAuthRedirects {
		http.Error(w, "login did not establish a session at the authorization endpoint after "+strconv.Itoa(n)+
			" attempts — the session must be a cookie sent on this domain, not a localStorage bearer", http.StatusLoopDetected)
		return
	}
	ret := *r.URL
	q := ret.Query()
	q.Set("_authretry", strconv.Itoa(authRetryCount(r)+1))
	ret.RawQuery = q.Encode()
	http.Redirect(w, r, h.LoginURL+"?return="+url.QueryEscape(ret.RequestURI()), http.StatusFound)
}

func authRetryCount(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("_authretry"))
	return n
}

func (h *OAuthASHandler) redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, code, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// renderConsent shows (and binds into the form) the effective granted scopes —
// not the raw request — so what the user approves is exactly what the code stores.
func (h *OAuthASHandler) renderConsent(w http.ResponseWriter, r *http.Request, client *port.OAuthClient, req port.AuthorizeRequest, scopes []string) {
	view := ConsentView{
		ClientName: clientLabel(client),
		Scopes:     scopes,
		Action:     authserver.OAuthAuthorizePath,
		Fields: map[string]string{
			"response_type":         "code",
			"client_id":             req.ClientID,
			"redirect_uri":          req.RedirectURI,
			"scope":                 strings.Join(scopes, " "),
			"state":                 req.State,
			"code_challenge":        req.CodeChallenge,
			"code_challenge_method": req.CodeChallengeMethod,
			"resource":              req.Resource,
		},
	}
	if h.Consent != nil {
		h.Consent(w, r, view)
		return
	}
	if tok, err := h.csrfGuard(r).Issue(w); err == nil {
		view.Fields["csrf"] = tok
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTemplate.Execute(w, view)
}

func clientLabel(c *port.OAuthClient) string {
	if c.Name != "" {
		return c.Name
	}
	return c.ClientID
}

// extractClientAuth reads client credentials and records the transport so the
// AS can enforce the client's registered token_endpoint_auth_method.
func extractClientAuth(r *http.Request) port.ClientAuth {
	if id, secret, ok := r.BasicAuth(); ok {
		return port.ClientAuth{ClientID: id, ClientSecret: secret, Method: "client_secret_basic"}
	}
	id := strings.TrimSpace(r.PostForm.Get("client_id"))
	secret := strings.TrimSpace(r.PostForm.Get("client_secret"))
	method := "none"
	if secret != "" {
		method = "client_secret_post"
	}
	return port.ClientAuth{ClientID: id, ClientSecret: secret, Method: method}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeOAuthError returns RFC 6749 protocol errors to the client verbatim, but
// logs internal errors (DB/signer/rand) server-side and replies with a generic
// server_error/500 so their detail never leaks and a failure is never silent.
func (h *OAuthASHandler) writeOAuthError(w http.ResponseWriter, err error) {
	code, ok := authserver.ProtocolErrorCode(err)
	if !ok {
		if h.Journal != nil {
			h.Journal.Error("oauth/as: " + err.Error())
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	status := http.StatusBadRequest
	if code == "invalid_client" {
		status = http.StatusUnauthorized
	}
	writeJSON(w, status, map[string]string{"error": code})
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Authorize</title></head><body>
<h1>Authorize {{.ClientName}}</h1>
<p>{{.ClientName}} is requesting access to your account.</p>
{{if .Scopes}}<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>{{end}}
<form method="post" action="{{.Action}}">
{{range $k, $v := .Fields}}<input type="hidden" name="{{$k}}" value="{{$v}}">
{{end}}<button type="submit" name="approve" value="true">Approve</button>
<button type="submit" name="approve" value="false">Deny</button>
</form></body></html>`))
