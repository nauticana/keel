package handler

import (
	"net/http"

	kcommon "github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/payment"
)

// UserPaymentMethodHandler exposes the one custom endpoint for the
// basis user_payment_method table — set-default. List and Delete are
// served by keel's generic REST CRUD against the UserSpecific basis
// table.
//
// SetDefault is registered via the table_action framework (basis
// table_action row + USER_PAYMENT_METHOD/SET_DEFAULT authorization)
// at the conventional URL POST /<rest_prefix>/v1/user_payment_method/set_default
// — so the button auto-renders in sail's generic CRUD views and the
// auth gate flows through WrapTableAction.
type UserPaymentMethodHandler struct {
	AbstractHandler
	DB      data.DatabaseRepository
	Service *payment.UserPaymentMethodService
}

// Routes returns the table-action route for SetDefault. prefix is the
// REST prefix INCLUDING the version segment (typically "/api/v1") —
// downstream apps pass the same shape they use for other handlers
// (PayoutHandler, etc.).
func (h *UserPaymentMethodHandler) Routes(prefix string) map[string]func(w http.ResponseWriter, r *http.Request) {
	if h.Service == nil {
		return map[string]func(w http.ResponseWriter, r *http.Request){}
	}
	return map[string]func(w http.ResponseWriter, r *http.Request){
		TableActionPath(prefix, "user_payment_method", "set_default"): WrapTableAction(h.DB, h.UserService,
			"USER_PAYMENT_METHOD", "SET_DEFAULT", "user_payment_method",
			h.setDefault),
	}
}

type paymentMethodIDRequest struct {
	ID int64 `json:"id"`
}

// setDefault is the actual SetDefault handler — invoked by
// WrapTableAction after the authorization gate. Renamed to lowercase
// so it's only callable through the wrapper (consumers must go through
// Routes()).
func (h *UserPaymentMethodHandler) setDefault(w http.ResponseWriter, r *http.Request) {
	var req paymentMethodIDRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if err := h.Service.SetDefault(r.Context(), session.Id, req.ID); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	kcommon.WriteJSON(w, http.StatusOK, map[string]string{"message": "set as default"})
}
