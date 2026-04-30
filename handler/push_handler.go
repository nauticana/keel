package handler

import (
	"net/http"

	"github.com/nauticana/keel/common"
)

// PushHandler handles mobile push-token registration and revocation.
// Register is called by the mobile SDK after login succeeds. Revoke is
// called on logout. Actual notification dispatch is done server-side by
// whichever component decides a push is warranted (a job worker, a
// domain event handler, etc.); this handler only manages the token list.
type PushHandler struct {
	AbstractHandler
}

// GetAuthRoutes returns authenticated push-management routes.
func (h *PushHandler) GetAuthRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.RestPrefix + "/push/register": h.Register,
		common.RestPrefix + "/push/revoke":   h.Revoke,
	}
}

// Register is the endpoint the mobile client calls on every app-launch:
// POST /api/push/register
//
//	{ "platform": "I|A|W", "token": "<FCM token>", "appVersion": "1.2.3", "deviceModel": "iPhone 15" }
//
// Idempotent — re-registering the same (user, token) refreshes the row's
// metadata and re-activates it if it had been revoked.
func (h *PushHandler) Register(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Platform    string `json:"platform"`
		Token       string `json:"token"`
		AppVersion  string `json:"appVersion"`
		DeviceModel string `json:"deviceModel"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if !h.RequireFields(w, map[string]string{"platform": req.Platform, "token": req.Token}) {
		return
	}
	if err := h.UserService.RegisterDeviceToken(session.Id, req.Platform, req.Token, req.AppVersion, req.DeviceModel); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to register device")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"message": "Device registered"})
}

// Revoke is called by the mobile client on logout:
// POST /api/push/revoke  { "token": "<FCM token>" }
//
// Only marks the row inactive — history is preserved for audit.
func (h *PushHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if !h.RequireFields(w, map[string]string{"token": req.Token}) {
		return
	}
	if err := h.UserService.RevokeDeviceToken(session.Id, req.Token); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to revoke device")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"message": "Device revoked"})
}
