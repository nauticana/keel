package handler

import (
	"errors"
	"net/http"

	kcommon "github.com/nauticana/keel/common"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

// UserPaymentMethodHandler exposes the custom endpoints for the basis
// user_payment_method table — set_default and remove (detach at the provider,
// then delete; generic REST DELETE is not granted so no client can skip the
// detach). List is served by keel's generic REST CRUD.
//
// Both are table actions (basis table_action rows + USER_PAYMENT_METHOD
// authorization) at POST /<rest_prefix>/v1/user_payment_method/<action>, so
// the buttons auto-render in sail's generic CRUD views and the auth gate
// flows through WrapTableAction.
type UserPaymentMethodHandler struct {
	AbstractHandler
	DB      port.DatabaseRepository
	Service *payment.UserPaymentMethodService
}

// Routes returns the table-action routes. prefix is the
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
		TableActionPath(prefix, "user_payment_method", "remove"): WrapTableAction(h.DB, h.UserService,
			"USER_PAYMENT_METHOD", "REMOVE", "user_payment_method",
			h.remove),
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
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
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

func (h *UserPaymentMethodHandler) remove(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req paymentMethodIDRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if err := h.Service.Remove(r.Context(), session.Id, req.ID); err != nil {
		if errors.Is(err, payment.ErrPaymentMethodNotFound) {
			h.WriteError(w, http.StatusNotFound, "Not Found", err.Error())
			return
		}
		h.WriteServiceError(w, r, err)
		return
	}
	kcommon.WriteJSON(w, http.StatusOK, map[string]string{"message": "removed"})
}
