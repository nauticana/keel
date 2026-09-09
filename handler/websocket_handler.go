package handler

import (
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// WebSocketHandler upgrades /public/ws for an authenticated user. Browsers
// cannot set Authorization on the handshake, so the JWT may arrive as ?token=.
type WebSocketHandler struct {
	AbstractHandler
	Hub port.WebSocketHub
}

func (h *WebSocketHandler) GetPublicRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.PublicPrefix + "/ws": h.Connect,
	}
}

func (h *WebSocketHandler) Connect(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	session := h.ParseSession(r)
	if session == nil {
		if tok := r.URL.Query().Get("token"); tok != "" {
			session, _ = h.UserService.ParseJWT(tok)
		}
	}
	if session == nil {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or missing session")
		return
	}
	if h.Hub == nil {
		h.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "websocket hub not configured")
		return
	}
	h.Hub.HandleUpgrade(w, r, session.Id)
}
