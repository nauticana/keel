package handler

import (
	"net/http"

	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

func init() {
	RegisterErrorCode(user.ErrAccountState, http.StatusConflict, "account_state")
	RegisterErrorCode(user.ErrSelfAction, http.StatusConflict, "self_action")
	RegisterErrorCode(user.ErrReasonTooLong, http.StatusBadRequest, "reason_too_long")
}

// AccountLockHandler serves the lock and unlock table actions of user_account.
type AccountLockHandler struct {
	AbstractHandler
	DB port.DatabaseRepository
}

// Routes mounts user_account/lock and user_account/unlock under prefix, gated
// by USER_ACCOUNT LOCK and UNLOCK.
func (h *AccountLockHandler) Routes(prefix string) map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		TableActionPath(prefix, "user_account", "lock"): WrapTableAction(
			h.DB, h.UserService, "USER_ACCOUNT", "LOCK", "user_account", h.lock),
		TableActionPath(prefix, "user_account", "unlock"): WrapTableAction(
			h.DB, h.UserService, "USER_ACCOUNT", "UNLOCK", "user_account", h.unlock),
	}
}

type accountLockRequest struct {
	ID     int    `json:"id"`
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

func (h *AccountLockHandler) lock(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, func(actorID int, req *accountLockRequest) error {
		return h.UserService.LockAccount(actorID, req.ID, req.Reason)
	})
}

func (h *AccountLockHandler) unlock(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, func(actorID int, req *accountLockRequest) error {
		return h.UserService.UnlockAccount(actorID, req.ID, req.Note)
	})
}

func (h *AccountLockHandler) serve(w http.ResponseWriter, r *http.Request, apply func(actorID int, req *accountLockRequest) error) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req accountLockRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if err := apply(session.Id, &req); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
