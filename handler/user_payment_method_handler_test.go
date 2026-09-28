package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/payment"
)

func TestUserPaymentMethodActionsRequirePost(t *testing.T) {
	h := &UserPaymentMethodHandler{Service: &payment.UserPaymentMethodService{}}
	for name, action := range map[string]http.HandlerFunc{
		"set_default": h.setDefault,
		"remove":      h.remove,
	} {
		w := httptest.NewRecorder()
		action(w, httptest.NewRequest(http.MethodGet, "/user_payment_method/"+name, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want %d", name, w.Code, http.StatusMethodNotAllowed)
		}
	}
}
