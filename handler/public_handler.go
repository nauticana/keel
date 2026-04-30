package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nauticana/keel/common"
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
}

func (h *PublicHandler) GetRoot(w http.ResponseWriter, r *http.Request) {
	if h.FolderHTML != "" {
		http.FileServer(http.Dir(h.FolderHTML)).ServeHTTP(w, r)
		return
	}
	w.Write([]byte("root is working"))
}

func (h *PublicHandler) LoginLocal(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Username          string `json:"username"`
		Password          string `json:"password"`
		DeviceFingerprint string `json:"deviceFingerprint"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "username and password are required")
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

	if partnerSession, err := h.UserService.GetUserById(session.Id); err == nil {
		session.PartnerId = partnerSession.PartnerId
	}

	if session.TwoFactorEnabled {
		trusted := false
		if req.DeviceFingerprint != "" {
			trusted, _ = h.UserService.IsTrustedDevice(session.Id, req.DeviceFingerprint)
		}
		if !trusted {
			loginToken, err := h.UserService.CreateLoginToken(session.Id)
			if err != nil {
				h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
				return
			}
			common.WriteJSON(w, http.StatusOK, map[string]any{
				"twoFactorRequired": true,
				"loginToken":        loginToken,
			})
			return
		}
	}

	menu, err := h.UserService.GetUserMenu(session.Id)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	token, err := h.UserService.CreateJWT(session)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	common.WriteJSON(w, http.StatusOK, map[string]any{
		"token":             token,
		"userId":            session.Id,
		"partnerId":         session.PartnerId,
		"menu":              menu,
		"twoFactorRequired": false,
	})
}

func (h *PublicHandler) LoginGoogle(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Code              string `json:"code"`
		RedirectURI       string `json:"redirectUri"`
		DeviceFingerprint string `json:"deviceFingerprint"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Code == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "code is required")
		return
	}
	// Fallback for popup/JS-SDK flows that use `postmessage` as the implicit redirect URI.
	if req.RedirectURI == "" {
		req.RedirectURI = "postmessage"
	}

	clientID := *common.GoogleClientID
	if clientID == "" {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "google_client_id flag is not configured")
		return
	}
	clientSecret, err := h.Secrets.GetSecret(r.Context(), "google_client_secret")
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to retrieve client secret")
		return
	}

	form := url.Values{
		"code":          {req.Code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {req.RedirectURI},
		"grant_type":    {"authorization_code"},
	}
	tokenReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to build token request")
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp, err := common.HTTPClient().Do(tokenReq)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to exchange token")
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, tokenResp.Body)
		_ = tokenResp.Body.Close()
	}()

	var tokenData struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to parse token response")
		return
	}
	if tokenData.Error != "" || tokenData.AccessToken == "" {
		detail := "token exchange failed"
		if tokenData.Error != "" {
			detail = "token exchange failed: " + tokenData.Error
			if tokenData.ErrorDescription != "" {
				detail += " — " + tokenData.ErrorDescription
			}
		}
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", detail)
		return
	}

	userInfoReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to build user-info request")
		return
	}
	userInfoReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	userInfoResp, err := common.HTTPClient().Do(userInfoReq)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to fetch user info")
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, userInfoResp.Body)
		_ = userInfoResp.Body.Close()
	}()

	var userInfo struct {
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
	}
	if err := json.NewDecoder(userInfoResp.Body).Decode(&userInfo); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to parse user info")
		return
	}
	if !userInfo.VerifiedEmail {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "email not verified")
		return
	}

	session, err := h.UserService.GetUserByEmail(userInfo.Email)
	if err != nil {
		// Same generic message as the password path — Google login can't
		// be allowed to leak whether the email is registered.
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid credentials")
		return
	}
	// GetUserByEmail no longer logs a phantom Login row (P0-17). Issue the
	// real activity entry now that we're committing to a JWT for this user.
	_ = h.UserService.AddUserHistory(session.Id, 0, TrustedClientIP(r), "L", "A", "google")

	if session.TwoFactorEnabled {
		trusted := false
		if req.DeviceFingerprint != "" {
			trusted, _ = h.UserService.IsTrustedDevice(session.Id, req.DeviceFingerprint)
		}
		if !trusted {
			loginToken, err := h.UserService.CreateLoginToken(session.Id)
			if err != nil {
				h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
				return
			}
			common.WriteJSON(w, http.StatusOK, map[string]any{
				"twoFactorRequired": true,
				"loginToken":        loginToken,
			})
			return
		}
	}

	menu, err := h.UserService.GetUserMenu(session.Id)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	token, err := h.UserService.CreateJWT(session)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	common.WriteJSON(w, http.StatusOK, map[string]any{
		"token":             token,
		"userId":            session.Id,
		"partnerId":         session.PartnerId,
		"menu":              menu,
		"twoFactorRequired": false,
	})
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
	if req.Email == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "email is required")
		return
	}
	if req.UserName == "" {
		req.UserName = req.Email
	}
	if err := h.RegisterService.SendConfirmation(r.Context(), &req); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to send confirmation")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "confirmation sent"})
}

func (h *PublicHandler) ConfirmRegistration(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	code := r.URL.Query().Get("code")
	if email == "" || code == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "email and code are required")
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
	result, err := h.RegisterService.Register(r.Context(), email, confirmation)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{
		"status":          "registration confirmed",
		"partnerId":       result.PartnerID,
		"planId":          result.PlanID,
		"paymentRequired": result.PaymentRequired,
		"paymentUrl":      result.PaymentURL,
	})
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
