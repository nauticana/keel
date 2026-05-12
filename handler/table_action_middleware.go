package handler

import (
	"net/http"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

// TableActionPath returns the conventional URL where a TableAction
// handler is mounted. Callers compose it inside their existing
// Routes(prefix) map. The path shape is `{prefix}/{table}/{action}`
// — no `/action/` segment, no version suffix.
//
// action_name may not collide with the generic CRUD subpaths
// list / get / post / delete / get-paginated; insert validation in
// rest.RestService.Init rejects table_action rows that try to use
// those names at boot.
func TableActionPath(prefix, table, action string) string {
	return prefix + "/" + table + "/" + action
}

// WrapTableAction returns an http.HandlerFunc that runs the keel
// authorization check for a custom (auth_object, action) pair against
// the calling user, then delegates to `inner` when allowed. Denied
// callers receive 403 (RFC 7807).
//
// authObject is the uppercased table name (e.g. "USER_PAYMENT_METHOD",
// "PROJECT_WBS_ITEM"); action is the uppercased action name
// (e.g. "SET_DEFAULT", "ASSIGN"). scope is what the caller's grant's
// low_limit is compared against — typically the lowercase table name
// so an explicit grant `(role, USER_PAYMENT_METHOD, SET_DEFAULT,
// low_limit='user_payment_method')` matches.
//
// Downstream apps wire one of these per (table, action) inside their
// existing handler's Routes(prefix) map:
//
//	keel.TableActionPath(prefix, "user_payment_method", "set_default"):
//	    keel.WrapTableAction(db, userSvc, "USER_PAYMENT_METHOD", "SET_DEFAULT",
//	        "user_payment_method", h.SetDefault),
func WrapTableAction(db data.DatabaseRepository, userSvc user.UserService, authObject, action, scope string, inner http.HandlerFunc) http.HandlerFunc {
	h := &AbstractHandler{UserService: userSvc}
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := h.RequireSession(w, r)
		if !ok {
			return
		}
		allowed, _ := db.CheckActionPermission(r.Context(), session.Id, authObject, action, scope)
		if !allowed {
			h.WriteError(w, http.StatusForbidden, "Forbidden",
				"missing permission "+authObject+"/"+action+" on "+scope)
			return
		}
		inner(w, r)
	}
}

// IsReservedActionName re-exports model.IsReservedActionName so
// handler-side validation reads naturally without importing model
// directly. Kept here as a thin alias; see model.ReservedActionNames
// for the actual set.
func IsReservedActionName(actionName string) bool {
	return model.IsReservedActionName(actionName)
}
