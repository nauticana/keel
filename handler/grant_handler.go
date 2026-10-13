package handler

import (
	"context"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/oauth/authserver"
)

func init() {
	RegisterErrorCode(authserver.ErrGrantNotFound, http.StatusNotFound, "grant_not_found")
}

// Grants is the grant behavior exposed over HTTP.
type Grants interface {
	List(ctx context.Context, userID int64) ([]authserver.Grant, error)
	Revoke(ctx context.Context, userID int64, clientID string) error
}

var _ Grants = (*authserver.GrantService)(nil)

// GrantHandler serves the caller's grants to clients of the local
// authorization server.
type GrantHandler struct {
	AbstractHandler
	Grants Grants
}

func (h *GrantHandler) GetAuthRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.RestPrefix + "/user/oauth-grants":        h.List,
		common.RestPrefix + "/user/oauth-grants/revoke": h.Revoke,
	}
}

// List: GET → []authserver.Grant.
func (h *GrantHandler) List(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	grants, err := h.Grants.List(r.Context(), int64(session.Id))
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, grants)
}

// Revoke: POST {"clientId"} → 204.
func (h *GrantHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		ClientID string `json:"clientId"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if err := h.Grants.Revoke(r.Context(), int64(session.Id), req.ClientID); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
