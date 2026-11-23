package handler

import (
	"net/http"
	"strings"

	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

func init() {
	RegisterErrorCode(user.ErrAccountState, http.StatusConflict, "account_state")
	RegisterErrorCode(user.ErrSelfAction, http.StatusConflict, "self_action")
	RegisterErrorCode(user.ErrReasonTooLong, http.StatusBadRequest, "reason_too_long")
}

// AccountLockHandler serves the status table actions of user_account: lock,
// unlock, expire and activate.
type AccountLockHandler struct {
	AbstractHandler
	DB port.DatabaseRepository
}

type accountStatusAction func(users user.UserService, actorID, userID int, reason string) error

// Routes mounts user_account/{lock,unlock,expire,activate} under prefix, each
// gated by USER_ACCOUNT and its upper-cased name.
func (h *AccountLockHandler) Routes(prefix string) map[string]func(http.ResponseWriter, *http.Request) {
	routes := map[string]func(http.ResponseWriter, *http.Request){}
	for name, apply := range map[string]accountStatusAction{
		"lock":     user.UserService.LockAccount,
		"unlock":   user.UserService.UnlockAccount,
		"expire":   user.UserService.ExpireAccount,
		"activate": user.UserService.ActivateAccount,
	} {
		routes[TableActionPath(prefix, "user_account", name)] = WrapTableAction(
			h.DB, h.UserService, "USER_ACCOUNT", strings.ToUpper(name), "user_account", h.serve(apply))
	}
	return routes
}

// serve reads {"id", "reason"}; unlock and activate name the text "note".
func (h *AccountLockHandler) serve(apply accountStatusAction) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.RequireMethod(w, r, http.MethodPost) {
			return
		}
		var req struct {
			ID     int    `json:"id"`
			Reason string `json:"reason"`
			Note   string `json:"note"`
		}
		session, ok := h.ReadAuthRequest(w, r, &req)
		if !ok {
			return
		}
		text := req.Reason
		if text == "" {
			text = req.Note
		}
		if err := apply(h.UserService, session.Id, req.ID, text); err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
