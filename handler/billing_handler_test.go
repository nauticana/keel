package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/billing"
)

type fakeManager struct {
	err    error
	planID string
}

func (f *fakeManager) CancelAtPeriodEnd(context.Context, int64) error { return f.err }
func (f *fakeManager) ChangePlan(_ context.Context, _ int64, planID string) error {
	f.planID = planID
	return f.err
}
func (f *fakeManager) PortalURL(context.Context, int64) (string, error) {
	return "https://portal", f.err
}

func billingRequest(h http.HandlerFunc, path, body string) int {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ok")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code
}

func TestBillingHandler(t *testing.T) {
	readOnly := &BillingHandler{AbstractHandler: AbstractHandler{UserService: intentUsers{}}}
	if _, ok := readOnly.Routes()["/api/billing/subscription/cancel"]; ok {
		t.Fatal("cancel mounted without a subscription manager")
	}

	manager := &fakeManager{}
	h := &BillingHandler{AbstractHandler: AbstractHandler{UserService: intentUsers{}}, Subscriptions: manager}
	if code := billingRequest(h.ChangePlan(), "/api/billing/subscription/change", `{}`); code != http.StatusBadRequest {
		t.Fatalf("missing planId: %d", code)
	}
	if code := billingRequest(h.ChangePlan(), "/api/billing/subscription/change", `{"planId":"PRO"}`); code != http.StatusOK || manager.planID != "PRO" {
		t.Fatalf("change: %d plan=%q", code, manager.planID)
	}
	manager.err = billing.ErrNoProviderSubscription
	if code := billingRequest(h.Cancel(), "/api/billing/subscription/cancel", ""); code != http.StatusConflict {
		t.Fatalf("unmanaged cancel: %d", code)
	}
}
