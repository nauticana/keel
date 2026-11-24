package handler

import (
	"net/http"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/realtime"
)

func init() {
	RegisterErrorMessage(realtime.ErrTicket, http.StatusUnauthorized, "invalid_ticket", "connection ticket is invalid, used or expired")
}

// WebSocketHandler upgrades /public/ws for an authenticated user. Browsers
// cannot set Authorization on the handshake, so they present a ?ticket= minted
// by POST /api/ws/ticket; nil Tickets refuses both.
type WebSocketHandler struct {
	AbstractHandler
	Hub     port.WebSocketHub
	Tickets *realtime.TicketService
}

func (h *WebSocketHandler) GetPublicRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.PublicPrefix + "/ws": h.Connect,
	}
}

func (h *WebSocketHandler) GetAuthRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.WebSocketTicketRoute: h.Ticket,
	}
}

// Ticket answers {"ticket", "expiresIn"}, expiresIn in seconds.
func (h *WebSocketHandler) Ticket(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if h.Tickets == nil {
		h.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "websocket tickets not configured")
		return
	}
	ttl := config.Config().WebSocketTicketTTL
	ticket, err := h.Tickets.Mint(r.Context(), session.Id, ttl)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	common.WriteJSON(w, http.StatusOK, map[string]any{"ticket": ticket, "expiresIn": int32(ttl / time.Second)})
}

func (h *WebSocketHandler) Connect(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	if h.Hub == nil {
		h.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "websocket hub not configured")
		return
	}
	userID := h.GetUser(r)
	if ticket := r.URL.Query().Get("ticket"); userID <= 0 && ticket != "" && h.Tickets != nil {
		var err error
		if userID, err = h.Tickets.Redeem(r.Context(), ticket, config.Config().WebSocketTicketTTL); err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
	}
	if userID <= 0 {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or missing session")
		return
	}
	h.Hub.HandleUpgrade(w, r, userID)
}
