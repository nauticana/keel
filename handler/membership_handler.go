package handler

import (
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

const maxMembershipReason = 200

func init() {
	RegisterErrorCode(user.ErrNoMembership, http.StatusNotFound, "no_membership")
}

// MembershipHandler ends partner memberships. The partner always comes from
// the caller's session.
type MembershipHandler struct {
	AbstractHandler
	DB port.DatabaseRepository
}

// Routes mounts partner_user/end and partner_user/directory under apiPrefix,
// gated by PARTNER_USER END and PARTNER_USER DIRECTORY.
func (h *MembershipHandler) Routes(apiPrefix string) map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		TableActionPath(apiPrefix, "partner_user", "end"): WrapTableAction(
			h.DB, h.UserService, "PARTNER_USER", "END", "partner_user", h.End),
		TableActionPath(apiPrefix, "partner_user", "directory"): WrapTableAction(
			h.DB, h.UserService, "PARTNER_USER", "DIRECTORY", "partner_user", h.Directory),
	}
}

// Directory lists the current members of the session partner, ids and
// names only; ?q= filters by name.
func (h *MembershipHandler) Directory(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	partnerID, ok := h.RequirePartner(w, r)
	if !ok {
		return
	}
	members, err := h.UserService.Members(partnerID, r.URL.Query().Get("q"))
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, members)
}

// End ends a user's membership of the session partner and revokes the
// sessions that could reach it.
func (h *MembershipHandler) End(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		UserID int    `json:"userId"`
		Reason string `json:"reason"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if session.PartnerId <= 0 {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "No partner associated with session")
		return
	}
	if req.UserID <= 0 || len(req.Reason) > maxMembershipReason {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "userId is required and reason is at most 200 bytes")
		return
	}
	if err := h.UserService.EndMembership(session.PartnerId, req.UserID, req.Reason); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"ended": req.UserID})
}
