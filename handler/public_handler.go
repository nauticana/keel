package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/connect"
	"github.com/nauticana/keel/oauth/oidc"
	"github.com/nauticana/keel/rest"
	"github.com/nauticana/keel/secret"
	"github.com/nauticana/keel/user"
)

type PublicHandler struct {
	AbstractHandler
	RestService     *rest.RestService
	RegisterService *user.RegistrationService
	Secrets         secret.SecretProvider
	FolderHTML      string
	// Handoff, initialized, mounts the exchange of a HandoffCode for tokens.
	Handoff *connect.NonceService
	// GoogleCode redeems LoginGoogle's code; nil uses Google's endpoints.
	GoogleCode *oidc.GoogleCode
}

// GetPublicRoutes returns the unauthenticated routes served by PublicHandler.
// Routes whose handler needs Secrets or RegisterService are only mounted when
// that dependency is set. password/forgot and password/change share
// ChangePassword: an empty old_password selects the reset-by-email path.
func (h *PublicHandler) GetPublicRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	routes := map[string]func(w http.ResponseWriter, r *http.Request){
		common.PublicPrefix + "/login/local":     h.LoginLocal,
		common.PublicPrefix + "/password/policy": h.GetPasswordPolicy,
		common.PublicPrefix + "/token/refresh":   h.RefreshToken,
		common.PublicPrefix + "/logout":          h.Logout,
	}
	if h.Secrets != nil {
		routes[common.PublicPrefix+"/login/gmail"] = h.LoginGoogle
	}
	if h.RegisterService != nil {
		routes[common.PublicPrefix+"/register"] = h.AddRegistrationRequest
		routes[common.PublicPrefix+"/register/confirm"] = h.ConfirmRegistration
		routes[common.PublicPrefix+"/password/forgot"] = h.ChangePassword
		routes[common.PublicPrefix+"/password/change"] = h.ChangePassword
		routes[common.PublicPrefix+"/password/reset"] = h.ConfirmPasswordChange
		routes[common.PublicPrefix+"/plans"] = h.ListPublicPlans
	}
	if h.Handoff != nil {
		routes[common.PublicPrefix+"/register/exchange"] = h.ExchangeHandoff
	}
	return routes
}

// RefreshToken rotates the presented refresh token and returns a new pair.
// A revoked, reused or expired token is 401; the client must log in again.
func (h *PublicHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if !h.ReadRequest(w, r, &req) || !h.RequireFields(w, map[string]string{"refreshToken": req.RefreshToken}) {
		return
	}
	session, err := h.UserService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, user.ErrInvalidRefreshToken) {
			h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired refresh token")
			return
		}
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	token, err := h.UserService.CreateJWT(session)
	if err != nil {
		h.WriteRequestError(r, w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"refreshToken": session.NewRefreshToken,
		"userId":       session.Id,
		"partnerId":    session.PartnerId,
	})
}

// Logout revokes the presented refresh token. Always 200: an unknown token
// is already logged out.
func (h *PublicHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if !h.ReadRequest(w, r, &req) || !h.RequireFields(w, map[string]string{"refreshToken": req.RefreshToken}) {
		return
	}
	if err := h.UserService.RevokeRefreshToken(req.RefreshToken); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to revoke token")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"message": "Logged out"})
}

func (h *PublicHandler) GetRoot(w http.ResponseWriter, r *http.Request) {
	if h.FolderHTML != "" {
		http.FileServer(http.Dir(h.FolderHTML)).ServeHTTP(w, r)
		return
	}
	w.Write([]byte("root is working"))
}

// GetPasswordPolicy exposes the global password rules for pre-submit validation.
// Public and non-secret; the server stays the authoritative gate.
func (h *PublicHandler) GetPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	common.WriteJSON(w, http.StatusOK, h.UserService.GetPasswordPolicy().ClientView())
}

// secondFactorPending reports whether the sign-in stops here: an account with
// 2FA on a device that is not trusted gets a login token for the 2FA step in
// place of session tokens. It has written the response when it returns true.
func (h *PublicHandler) secondFactorPending(w http.ResponseWriter, r *http.Request, session *model.UserSession) bool {
	if !session.TwoFactorEnabled {
		return false
	}
	if secret := DefaultTrustedDeviceCookie.Get(r); secret != "" {
		if trusted, _ := h.UserService.IsTrustedDevice(session.Id, secret); trusted {
			return false
		}
	}
	loginToken, err := h.UserService.CreateLoginToken(session.Id, session.SignInMethod)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return true
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{
		"twoFactorRequired": true,
		"loginToken":        loginToken,
	})
	return true
}

func (h *PublicHandler) LoginLocal(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		SessionLimit
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "username and password are required")
		return
	}
	maxAge, err := req.MaxAge()
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}

	session, err := h.UserService.GetUserByLogin(req.Username, req.Password)
	if err != nil {
		// Generic message: never distinguish "user not found" from "wrong
		// password" or "account locked" — those branches let an attacker
		// enumerate valid usernames. The underlying err is captured server
		// side via the AddUserHistory rows GetUserByLogin already writes.
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid credentials")
		return
	}

	if err := h.UserService.CheckSignInMethod(session.Id, user.SignInPassword); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	session.SignInMethod = user.SignInPassword
	session.SessionMaxAge = maxAge

	if h.secondFactorPending(w, r, session) {
		return
	}

	menu, err := h.UserService.GetUserMenu(session.Id)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	resp, err := h.SessionTokens(session)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	resp["menu"] = menu
	resp["twoFactorRequired"] = false
	common.WriteJSON(w, http.StatusOK, resp)
}

func (h *PublicHandler) LoginGoogle(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirectUri"`
		SessionLimit
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Code == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "code is required")
		return
	}
	maxAge, err := req.MaxAge()
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	// Fallback for popup/JS-SDK flows that use `postmessage` as the implicit redirect URI.
	if req.RedirectURI == "" {
		req.RedirectURI = "postmessage"
	}

	clientID := config.Config().GoogleClientID
	if clientID == "" {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "google_client_id flag is not configured")
		return
	}
	clientSecret, err := h.Secrets.GetSecret(r.Context(), "google_client_secret")
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to retrieve client secret")
		return
	}

	exchange := h.GoogleCode
	if exchange == nil {
		exchange = &oidc.GoogleCode{}
	}
	a, err := exchange.Identity(r.Context(), clientID, clientSecret, req.Code, req.RedirectURI)
	var tokenErr *oidc.TokenError
	switch {
	case errors.As(err, &tokenErr):
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", tokenErr.Error())
		return
	case errors.Is(err, oidc.ErrEmailNotVerified):
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "email not verified")
		return
	case err != nil:
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to exchange token")
		return
	}
	identity := socialIdentity(oidc.ProviderGoogle, a)
	session, err := h.UserService.GetUserFromExternal(identity)
	if err != nil {
		if mapped := socialSignInError(err); mapped != nil {
			h.WriteServiceError(w, r, mapped)
			return
		}
		// Same generic message as the password path, so an unregistered email is not revealed.
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid credentials")
		return
	}
	if !h.admitExternalSignIn(w, r, session, identity) {
		return
	}
	session.SessionMaxAge = maxAge

	if h.secondFactorPending(w, r, session) {
		return
	}

	menu, err := h.UserService.GetUserMenu(session.Id)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	resp, err := h.SessionTokens(session)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	resp["menu"] = menu
	resp["twoFactorRequired"] = false
	common.WriteJSON(w, http.StatusOK, resp)
}

// ChangePassword serves both the reset-by-email request flow (no
// OldPassword) and the in-session password change (with OldPassword).
//
// Username enumeration is guarded by always returning the same 200
// "confirmation sent" response shape on the reset path regardless of
// whether the username actually maps to a user_account — an attacker
// cannot distinguish "we sent the email" from "no such user".
//
// On the in-session change path, the 401 message is generic for the
// same reason as LoginLocal.
func (h *PublicHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Username    string `json:"username"`
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Username == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "username is required")
		return
	}

	if req.OldPassword == "" {
		// Reset-by-email path. Resolve the username best-effort; on
		// unknown user, still return 200 so the caller can't tell the
		// difference. Internal errors (DB outage) DO surface as 500 so
		// operators see the breakage.
		if user, err := h.UserService.GetUserByUsername(req.Username); err == nil && user != nil {
			if sendErr := h.RegisterService.SendPasswordChangeConfirmation(r.Context(), user.Email); sendErr != nil {
				h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to send confirmation")
				return
			}
		}
		common.WriteJSON(w, http.StatusOK, map[string]string{"status": "confirmation sent"})
		return
	}

	if req.NewPassword == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "password is required")
		return
	}
	session, err := h.UserService.GetUserByLogin(req.Username, req.OldPassword)
	if err != nil {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid credentials")
		return
	}
	if err := h.UserService.SetPassword(session.Id, req.NewPassword); err != nil {
		// Policy-violation messages (length, complexity) are caller-safe
		// and useful — let those through. Other errors stay generic.
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}

// ConfirmPasswordChange completes the reset-by-email flow. All "user
// not found" / "code mismatch" branches collapse to the same generic
// 400 to prevent enumeration of valid (username, pending-code) pairs.
func (h *PublicHandler) ConfirmPasswordChange(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Code     string `json:"code"`
		Password string `json:"new_password"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Username == "" || req.Code == "" || req.Password == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "username, code, and password are required")
		return
	}
	code, err := strconv.Atoi(req.Code)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid or expired code")
		return
	}
	user, err := h.UserService.GetUserByUsername(req.Username)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid or expired code")
		return
	}
	if err := h.RegisterService.ConfirmPasswordChange(r.Context(), user.Email, code); err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid or expired code")
		return
	}
	if err := h.UserService.SetPassword(user.Id, req.Password); err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}

// AddRegistrationRequest accepts an unauthenticated registration payload
// and emails the confirmation code. The 200 response is identical
// regardless of whether the email already maps to a user_account, so an
// attacker cannot probe registered addresses through this endpoint.
func (h *PublicHandler) AddRegistrationRequest(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req user.PartnerRegistration
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if err := h.RegisterService.SendConfirmation(r.Context(), &req); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "confirmation sent"})
}

// ConfirmRegistration completes registration from ?email=&code= and returns
// the new session's tokens, with the partner when the registration had one.
func (h *PublicHandler) ConfirmRegistration(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	email := r.URL.Query().Get("email")
	code := r.URL.Query().Get("code")
	if email == "" || code == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "email and code are required")
		return
	}
	if len(code) > 9 {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid confirmation code")
		return
	}
	confirmation := 0
	for _, c := range code {
		if c < '0' || c > '9' {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid confirmation code")
			return
		}
		confirmation = confirmation*10 + int(c-'0')
	}
	session, created, err := h.RegisterService.Register(r.Context(), email, confirmation)
	if !h.checkoutTolerated(w, r, err) {
		return
	}
	resp, err := h.SessionTokens(session)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	resp["status"] = "registration confirmed"
	if created != nil {
		resp["planId"] = created.PlanID
		resp["paymentRequired"] = created.PaymentRequired
		resp["paymentUrl"] = created.PaymentURL
	}
	common.WriteJSON(w, http.StatusOK, resp)
}

// ListPublicPlans returns the subscription plans to the unauthenticated
// registration page so it can render a plan picker.
func (h *PublicHandler) ListPublicPlans(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	plans, err := h.RegisterService.ListPlans(r.Context())
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to list plans")
		return
	}
	common.WriteJSON(w, http.StatusOK, plans)
}
