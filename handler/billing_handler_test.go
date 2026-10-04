package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// grantDB allows exactly the listed actions on PARTNER_PLAN_SUBSCRIPTION.
type grantDB struct {
	port.DatabaseRepository
	actions map[string]bool
}

func (d grantDB) CheckActionPermission(_ context.Context, p model.Principal, object, action, scope string) (bool, bool) {
	return p.Valid() && object == SubscriptionAuthObject && scope == "partner_plan_subscription" && d.actions[action], false
}

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
	unwired := &BillingHandler{AbstractHandler: AbstractHandler{UserService: intentUsers{}}, Subscriptions: manager}
	if _, ok := unwired.Routes()["/api/billing/subscription/cancel"]; ok {
		t.Fatal("cancel mounted without a database to authorize it")
	}

	db := grantDB{actions: map[string]bool{"CHANGE": true, "CANCEL": true, "PORTAL": true}}
	h := &BillingHandler{AbstractHandler: AbstractHandler{UserService: intentUsers{}}, DB: db, Subscriptions: manager}
	routes := h.Routes()
	change, cancel := routes["/api/billing/subscription/change"], routes["/api/billing/subscription/cancel"]
	if code := billingRequest(change, "/api/billing/subscription/change", `{}`); code != http.StatusBadRequest {
		t.Fatalf("missing planId: %d", code)
	}
	if code := billingRequest(change, "/api/billing/subscription/change", `{"planId":"PRO"}`); code != http.StatusOK || manager.planID != "PRO" {
		t.Fatalf("change: %d plan=%q", code, manager.planID)
	}
	manager.err = billing.ErrNoProviderSubscription
	if code := billingRequest(cancel, "/api/billing/subscription/cancel", ""); code != http.StatusConflict {
		t.Fatalf("unmanaged cancel: %d", code)
	}
}

func TestBillingHandlerRequiresSubscriptionGrant(t *testing.T) {
	manager := &fakeManager{}
	h := &BillingHandler{AbstractHandler: AbstractHandler{UserService: intentUsers{}}, DB: grantDB{}, Subscriptions: manager}
	for path, body := range map[string]string{
		"/api/billing/subscription/cancel": "",
		"/api/billing/subscription/change": `{"planId":"PRO"}`,
		"/api/billing/portal":              "",
	} {
		if code := billingRequest(h.Routes()[path], path, body); code != http.StatusForbidden {
			t.Errorf("%s without grant: %d, want 403", path, code)
		}
	}
	if manager.planID != "" {
		t.Fatal("plan changed without a grant")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/billing/portal", nil)
	rec := httptest.NewRecorder()
	h.Routes()["/api/billing/portal"](rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d, want 401", rec.Code)
	}
}
