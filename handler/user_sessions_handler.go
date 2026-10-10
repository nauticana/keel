package handler

import (
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/user"
)

func init() {
	RegisterErrorCode(user.ErrSignInNetwork, http.StatusForbidden, "signin_network")
	RegisterErrorCode(user.ErrSessionNotFound, http.StatusNotFound, "session_not_found")
	RegisterErrorCode(user.ErrStepUpUnavailable, http.StatusServiceUnavailable, "stepup_unavailable")
}

// ListSessions returns the caller's live sign-in sessions, marking the one
// the request's token belongs to.
//
// GET /api/user/sessions
func (h *SecurityHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	sessions, err := h.UserService.Sessions(session.Id)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	for i := range sessions {
		sessions[i].Current = session.SessionID != 0 && sessions[i].ID == session.SessionID
	}
	common.WriteJSON(w, http.StatusOK, sessions)
}

// RevokeSession signs the caller out of one of their sessions.
//
// POST /api/user/sessions/revoke  { "id": <int64> }
func (h *SecurityHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if err := h.UserService.RevokeSession(session.Id, req.ID); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
