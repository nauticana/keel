package handler

import (
	"net/http"

	kcommon "github.com/nauticana/keel/common"
	"github.com/nauticana/keel/payment"
)

// UserPaymentMethodHandler exposes the one custom endpoint for the
// basis user_payment_method table — set-default. List and Delete are
// served by keel's generic REST CRUD (`GET` / `DELETE
// /api/user_payment_method`) because the table is UserSpecific (FK
// column is `user_id`), so the auto-filter already scopes reads + the
// owner-lock blocks cross-user writes.
//
// SetDefault stays custom because it's an atomic multi-row UPDATE
// ("clear every other row's is_default in the same statement as you
// flip the chosen one to true") that abstract single-row CRUD can't
// express without a racy two-step.
type UserPaymentMethodHandler struct {
	AbstractHandler
	Service *payment.UserPaymentMethodService
}

// Routes returns the single custom-endpoint map for this handler.
// Mount under the application's REST prefix (typically "/api/v1").
func (h *UserPaymentMethodHandler) Routes(prefix string) map[string]func(w http.ResponseWriter, r *http.Request) {
	if h.Service == nil {
		return map[string]func(w http.ResponseWriter, r *http.Request){}
	}
	return map[string]func(w http.ResponseWriter, r *http.Request){
		prefix + "/payment-methods/set-default": h.SetDefault,
	}
}

type paymentMethodIDRequest struct {
	ID int64 `json:"id"`
}

// SetDefault flips the chosen row to is_default and clears every other
// row owned by the caller in the same statement.
func (h *UserPaymentMethodHandler) SetDefault(w http.ResponseWriter, r *http.Request) {
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
