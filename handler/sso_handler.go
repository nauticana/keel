package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/oauth/connect"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/sso"
	"github.com/nauticana/keel/user"
)

const (
	ssoCookie        = "keel_sso"
	ssoLaunchPurpose = "sso_launch"
)

func init() {
	RegisterErrorCode(sso.ErrConnectionNotFound, http.StatusNotFound, "identity_provider_not_found")
	RegisterErrorCode(sso.ErrInvalidConfiguration, http.StatusBadRequest, "invalid_identity_provider")
	RegisterErrorCode(sso.ErrConnectionActive, http.StatusConflict, "identity_provider_active")
	RegisterErrorCode(sso.ErrNotTested, http.StatusConflict, "identity_provider_not_tested")
	RegisterErrorCode(sso.ErrNoIdentityDomain, http.StatusConflict, "identity_domain_required")
	RegisterErrorCode(sso.ErrTestMismatch, http.StatusForbidden, "sso_test_mismatch")
}

// ssoRedirectCodes are the error codes a browser is sent back with; anything
// else is server_error, with the cause only in the journal.
var ssoRedirectCodes = []struct {
	err  error
	code string
}{
	{sso.ErrUnavailable, "sso_unavailable"},
	{sso.ErrMFARequired, "mfa_required"},
	{sso.ErrEmailNotAllowed, "sso_email_not_allowed"},
	{sso.ErrNoAccount, "sso_no_account"},
	{sso.ErrOtherPartner, "sso_other_partner"},
	{sso.ErrTestMismatch, "sso_test_mismatch"},
	{sso.ErrSignInFailed, "sso_failed"},
	{user.ErrSSORequired, "sso_required"},
	{user.ErrAccountUnavailable, "account_unavailable"},
	{user.ErrIdentityLinked, "identity_linked"},
	{domain.ErrDomainNotProven, "domain_not_proven"},
}

// SSOHandler is the browser side of tenant single sign-on and the table
// actions that manage a partner's connection. Every redirect back to the
// application goes to FrontendReturnURL with one query parameter: code (a
// sign-in handoff code for /public/register/exchange), test=passed, or error
// (plus test=failed for a test).
type SSOHandler struct {
	AbstractHandler
	DB  port.DatabaseRepository
	SSO *sso.Service
	// Handoff stores sign-in handoff codes and test launch codes; the same
	// service as PublicHandler.Handoff.
	Handoff *connect.NonceService
	// PublicBaseURL is this API's origin; identity providers redirect to
	// PublicBaseURL + PublicPrefix + "/sso/callback".
	PublicBaseURL     string
	FrontendReturnURL string
	// ServiceProviderMetadata, when set (a *saml.Provider), mounts keel's
	// SAML service provider metadata for identity provider administrators.
	ServiceProviderMetadata interface {
		Metadata(callback string) ([]byte, error)
	}
}

// PublicRoutes mounts start, launch and callback. They are top-level browser
// navigations, never XHR, so the binding cookie is first-party.
func (h *SSOHandler) PublicRoutes() map[string]func(http.ResponseWriter, *http.Request) {
	routes := map[string]func(http.ResponseWriter, *http.Request){
		common.PublicPrefix + "/sso/start":    h.Start,
		common.PublicPrefix + "/sso/launch":   h.Launch,
		common.PublicPrefix + "/sso/callback": h.Callback,
	}
	if h.ServiceProviderMetadata != nil {
		routes[common.PublicPrefix+"/sso/saml/metadata"] = h.SAMLMetadata
	}
	return routes
}

// SAMLMetadata serves keel's SAML service provider metadata.
func (h *SSOHandler) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	md, err := h.ServiceProviderMetadata.Metadata(h.callbackURL())
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(md)
}

// Routes mounts the partner_identity_provider table actions under apiPrefix.
func (h *SSOHandler) Routes(apiPrefix string) map[string]func(http.ResponseWriter, *http.Request) {
	action := func(name string, inner http.HandlerFunc) http.HandlerFunc {
		return WrapTableAction(h.DB, h.UserService, "PARTNER_IDENTITY_PROVIDER", strings.ToUpper(name), "partner_identity_provider", inner)
	}
	return map[string]func(http.ResponseWriter, *http.Request){
		TableActionPath(apiPrefix, "partner_identity_provider", "configure"): action("configure", h.Configure),
		TableActionPath(apiPrefix, "partner_identity_provider", "test"):      action("test", h.Test),
		TableActionPath(apiPrefix, "partner_identity_provider", "activate"):  action("activate", h.Activate),
		TableActionPath(apiPrefix, "partner_identity_provider", "disable"):   action("disable", h.Disable),
	}
}

// Start (GET ?email=) sends the browser to the identity provider of the
// organization holding the email's domain.
func (h *SSOHandler) Start(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	email := r.URL.Query().Get("email")
	if email == "" || len(email) > 254 {
		h.backToApp(w, r, url.Values{"error": {"sso_unavailable"}})
		return
	}
	target, key, err := h.SSO.Start(r.Context(), email, h.callbackURL())
	if err != nil {
		h.backToApp(w, r, url.Values{"error": {h.redirectCode(r, err)}})
		return
	}
	h.toIdentityProvider(w, r, key, target)
}

// Launch (GET ?code=) opens a test sign-in started by the test action.
func (h *SSOHandler) Launch(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	var launch struct {
		Key string `json:"k"`
		URL string `json:"u"`
	}
	payload, ok, err := h.Handoff.Consume(r.Context(), r.URL.Query().Get("code"), ssoLaunchPurpose, handoffTTLSeconds())
	if err != nil || !ok || json.Unmarshal([]byte(payload), &launch) != nil || launch.Key == "" {
		if err != nil {
			h.redirectCode(r, err)
		}
		h.backToApp(w, r, url.Values{"test": {"failed"}, "error": {"sso_failed"}})
		return
	}
	h.toIdentityProvider(w, r, launch.Key, launch.URL)
}

// Callback receives the identity provider's answer by query or form post.
func (h *SSOHandler) Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		h.RequireMethod(w, r, http.MethodGet)
		return
	}
	params := r.URL.Query()
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, config.Config().SSOMaxDocumentSize)
		if err := r.ParseForm(); err != nil {
			h.backToApp(w, r, url.Values{"error": {"sso_failed"}})
			return
		}
		params = r.PostForm
	}
	key := ""
	if c, err := r.Cookie(ssoCookie); err == nil {
		key = c.Value
	}
	http.SetCookie(w, h.cookie("", -1))
	outcome, err := h.SSO.Complete(r.Context(), key, h.callbackURL(), params)
	if err != nil {
		h.backToApp(w, r, url.Values{"error": {h.redirectCode(r, err)}})
		return
	}
	if outcome.Test {
		h.backToApp(w, r, url.Values{"test": {"passed"}})
		return
	}
	code, err := createHandoff(r.Context(), h.Handoff, outcome.Session, true)
	if err != nil {
		h.backToApp(w, r, url.Values{"error": {h.redirectCode(r, err)}})
		return
	}
	h.backToApp(w, r, url.Values{"code": {code}})
}

// Configure creates or edits the session partner's OpenID Connect connection.
// It takes JSON, or multipart when private_key is an uploaded PEM file.
func (h *SSOHandler) Configure(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok || !h.requirePartner(w, session.PartnerId) {
		return
	}
	cfg, err := readConfiguration(w, r)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	id, err := h.SSO.Configure(r.Context(), session.PartnerId, session.Id, cfg)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"id": id})
}

// Test returns the launch URL of a test sign-in by the calling administrator.
func (h *SSOHandler) Test(w http.ResponseWriter, r *http.Request) {
	id, session, ok := h.readConnectionAction(w, r)
	if !ok {
		return
	}
	target, key, err := h.SSO.BeginTest(r.Context(), session.PartnerId, session.Id, id, h.callbackURL())
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	payload, err := json.Marshal(map[string]string{"k": key, "u": target})
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	code, err := h.Handoff.Create(r.Context(), ssoLaunchPurpose, string(payload))
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"url": h.publicURL("/sso/launch") + "?" + url.Values{"code": {code}}.Encode()})
}

// Activate makes a tested connection the partner's active one.
func (h *SSOHandler) Activate(w http.ResponseWriter, r *http.Request) {
	id, session, ok := h.readConnectionAction(w, r)
	if !ok {
		return
	}
	if err := h.SSO.Activate(r.Context(), session.PartnerId, session.Id, id); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "status": sso.StatusActive})
}

// Disable stops a connection and signs out the sessions it signed in.
func (h *SSOHandler) Disable(w http.ResponseWriter, r *http.Request) {
	id, session, ok := h.readConnectionAction(w, r)
	if !ok {
		return
	}
	if err := h.SSO.Disable(r.Context(), session.PartnerId, session.Id, id); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "status": sso.StatusDisabled})
}

func (h *SSOHandler) readConnectionAction(w http.ResponseWriter, r *http.Request) (int64, *sessionView, bool) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return 0, nil, false
	}
	var req struct {
		ID int64 `json:"id"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok || !h.requirePartner(w, session.PartnerId) {
		return 0, nil, false
	}
	if req.ID <= 0 {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "id is required")
		return 0, nil, false
	}
	return req.ID, &sessionView{Id: session.Id, PartnerId: session.PartnerId}, true
}

// sessionView is the part of the caller's session an action needs.
type sessionView struct {
	Id        int
	PartnerId int64
}

func (h *SSOHandler) requirePartner(w http.ResponseWriter, partnerID int64) bool {
	if partnerID <= 0 {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "No partner associated with session")
		return false
	}
	return true
}

func (h *SSOHandler) toIdentityProvider(w http.ResponseWriter, r *http.Request, key, target string) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" {
		h.backToApp(w, r, url.Values{"error": {"sso_failed"}})
		return
	}
	http.SetCookie(w, h.cookie(key, config.Config().OAuthStateTTLSeconds))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *SSOHandler) backToApp(w http.ResponseWriter, r *http.Request, q url.Values) {
	w.Header().Set("Cache-Control", "no-store")
	sep := "?"
	if strings.Contains(h.FrontendReturnURL, "?") {
		sep = "&"
	}
	http.Redirect(w, r, h.FrontendReturnURL+sep+q.Encode(), http.StatusFound)
}

// cookie binds a pending sign-in to the browser. SameSite=None lets it ride
// a SAML response's cross-site POST; the binding rests on its secret value,
// which only this browser holds.
func (h *SSOHandler) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: ssoCookie, Value: value, Path: common.PublicPrefix + "/sso", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode}
}

func (h *SSOHandler) callbackURL() string { return h.publicURL("/sso/callback") }

func (h *SSOHandler) publicURL(path string) string {
	return strings.TrimRight(h.PublicBaseURL, "/") + common.PublicPrefix + path
}

// redirectCode maps err to a browser error code and journals anything that
// is not an expected refusal.
func (h *SSOHandler) redirectCode(r *http.Request, err error) string {
	for _, c := range ssoRedirectCodes {
		if errors.Is(err, c.err) {
			if errors.Is(err, sso.ErrSignInFailed) && h.Journal != nil {
				h.Journal.Warning(fmt.Sprintf("sso %s: %v", r.URL.Path, err))
			}
			return c.code
		}
	}
	if h.Journal != nil {
		h.Journal.Error(fmt.Sprintf("sso %s: %v", r.URL.Path, err))
	}
	return "server_error"
}

// readConfiguration reads the configure action's parameters.
func readConfiguration(w http.ResponseWriter, r *http.Request) (sso.Configuration, error) {
	limit := config.Config().MaxRequestSize
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	var in struct {
		ID             json.Number `json:"id"`
		Caption        string      `json:"caption"`
		Issuer         string      `json:"issuer"`
		ClientID       string      `json:"client_id"`
		ClientAuth     string      `json:"client_auth"`
		ClientSecret   string      `json:"client_secret"`
		PrivateKey     string      `json:"private_key"`
		Protocol       string      `json:"protocol"`
		IdPMetadata    string      `json:"idp_metadata"`
		OperatorClient string      `json:"operator_client"`
		SubjectClaim   string      `json:"subject_claim"`
		EmailClaim     string      `json:"email_claim"`
		Scopes         string      `json:"scopes"`
		RequireMFA     any         `json:"require_mfa"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(limit); err != nil {
			return sso.Configuration{}, fmt.Errorf("%w: form: %v", sso.ErrInvalidConfiguration, err)
		}
		f := r.FormValue
		in.ID, in.Caption, in.Issuer, in.ClientID, in.ClientAuth = json.Number(f("id")), f("caption"), f("issuer"), f("client_id"), f("client_auth")
		in.ClientSecret, in.OperatorClient, in.SubjectClaim, in.EmailClaim, in.Scopes, in.RequireMFA = f("client_secret"), f("operator_client"), f("subject_claim"), f("email_claim"), f("scopes"), f("require_mfa")
		in.Protocol, in.IdPMetadata = f("protocol"), f("idp_metadata")
		for field, target := range map[string]*string{"private_key": &in.PrivateKey, "idp_metadata": &in.IdPMetadata} {
			file, _, err := r.FormFile(field)
			if err != nil {
				continue
			}
			raw, err := io.ReadAll(io.LimitReader(file, limit))
			_ = file.Close()
			if err != nil {
				return sso.Configuration{}, fmt.Errorf("%w: %s: %v", sso.ErrInvalidConfiguration, field, err)
			}
			*target = string(raw)
		}
	} else {
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		if err := dec.Decode(&in); err != nil {
			return sso.Configuration{}, fmt.Errorf("%w: body: %v", sso.ErrInvalidConfiguration, err)
		}
		if err := requireJSONEOF(dec); err != nil {
			return sso.Configuration{}, fmt.Errorf("%w: body: %v", sso.ErrInvalidConfiguration, err)
		}
	}
	var id int64
	if in.ID != "" {
		v, err := strconv.ParseInt(string(in.ID), 10, 64)
		if err != nil || v < 0 {
			return sso.Configuration{}, fmt.Errorf("%w: id", sso.ErrInvalidConfiguration)
		}
		id = v
	}
	if in.ClientSecret != "" && in.PrivateKey != "" {
		return sso.Configuration{}, fmt.Errorf("%w: send a client secret or a private key, not both", sso.ErrInvalidConfiguration)
	}
	mfa, ok := in.RequireMFA.(bool)
	if s, isString := in.RequireMFA.(string); isString {
		mfa, ok = s == "true", s == "true" || s == "false" || s == ""
	}
	if !ok && in.RequireMFA != nil {
		return sso.Configuration{}, fmt.Errorf("%w: require_mfa", sso.ErrInvalidConfiguration)
	}
	return sso.Configuration{
		ID: id, Protocol: in.Protocol, IdPMetadata: in.IdPMetadata, Caption: in.Caption, Issuer: in.Issuer, ClientID: in.ClientID, ClientAuth: in.ClientAuth,
		Credential: in.ClientSecret + in.PrivateKey, OperatorClient: in.OperatorClient,
		SubjectClaim: in.SubjectClaim, EmailClaim: in.EmailClaim, Scopes: in.Scopes, RequireMFA: mfa,
	}, nil
}
