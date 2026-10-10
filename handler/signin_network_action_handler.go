package handler

import (
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

func init() {
	RegisterErrorCode(user.ErrSignInNetworkLockout, http.StatusConflict, "signin_network_lockout")
	RegisterErrorCode(common.ErrInvalidCIDRList, http.StatusBadRequest, "invalid_network_list")
}

// SignInNetworkActionHandler serves the replace table action of
// partner_signin_network: the session partner's sign-in networks are set as
// a whole, so an administrator cannot lock themselves out row by row.
type SignInNetworkActionHandler struct {
	AbstractHandler
	DB       port.DatabaseRepository
	Networks *user.SignInNetworkService
}

// Routes returns the table-action route; prefix includes the version segment.
func (h *SignInNetworkActionHandler) Routes(prefix string) map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		TableActionPath(prefix, "partner_signin_network", "replace"): WrapTableAction(h.DB, h.UserService,
			"PARTNER_SIGNIN_NETWORK", "REPLACE", "partner_signin_network", h.replace),
	}
}

// replace sets the caller's partner networks; an empty list allows any address.
func (h *SignInNetworkActionHandler) replace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDRs string `json:"cidrs"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if err := h.Networks.Replace(r.Context(), session.PartnerId, req.CIDRs, common.TrustedClientIP(r)); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
