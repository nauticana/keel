package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/common"
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
	err      error
	planID   string
	terms    billing.BillingTerms
	overages []port.QuotaOverage
}

func (f *fakeManager) CheckChange(_ context.Context, _ int64, planID string) ([]port.QuotaOverage, error) {
	f.planID = planID
	return f.overages, f.err
}

func (f *fakeManager) CancelAtPeriodEnd(context.Context, int64) error { return f.err }
func (f *fakeManager) ChangePlan(_ context.Context, _ int64, planID string, terms billing.BillingTerms) (billing.ChangeOutcome, error) {
	f.planID, f.terms = planID, terms
	if planID == "FREE" {
		return billing.ChangeScheduled, f.err
	}
	return billing.ChangeApplied, f.err
}
func (f *fakeManager) PortalURL(context.Context, int64) (string, error) {
	return "https://portal", f.err
}

func billingRequest(h http.HandlerFunc, path, body string) int {
	code, _ := billingCall(h, path, body)
	return code
}

func billingCall(h http.HandlerFunc, path, body string) (int, string) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ok")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code, rec.Body.String()
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
	if code, body := billingCall(change, "/api/billing/subscription/change", `{"planId":"PRO"}`); code != http.StatusOK || manager.planID != "PRO" || !strings.Contains(body, `"changed"`) {
		t.Fatalf("change: %d plan=%q body=%s", code, manager.planID, body)
	}
	if manager.terms != (billing.BillingTerms{}) {
		t.Fatalf("no offer sent terms %+v", manager.terms)
	}
	annual := billing.BillingTerms{BillingCycle: billing.PeriodAnnual, TermType: billing.PeriodAnnual, TermCount: 1}
	if code := billingRequest(change, "/api/billing/subscription/change", `{"planId":"PRO","billingCycle":"A","termType":"A","termCount":1}`); code != http.StatusOK || manager.terms != annual {
		t.Fatalf("offer: %d terms=%+v", code, manager.terms)
	}
	for _, body := range []string{
		`{"planId":"PRO","billingCycle":"A"}`,
		`{"planId":"PRO","billingCycle":"YEAR","termType":"A"}`,
		`{"planId":"PRO","billingCycle":"a","termType":"a"}`,
		`{"planId":"PRO","billingCycle":"A","termType":"A","termCount":-1}`,
		`{"planId":"PRO","termCount":12}`,
	} {
		manager.planID = ""
		if code := billingRequest(change, "/api/billing/subscription/change", body); code != http.StatusBadRequest || manager.planID != "" {
			t.Errorf("%s: %d reached=%q", body, code, manager.planID)
		}
	}
	if code, body := billingCall(change, "/api/billing/subscription/change", `{"planId":"FREE"}`); code != http.StatusOK || !strings.Contains(body, `"scheduled"`) {
		t.Fatalf("scheduled change: %d body=%s", code, body)
	}
	manager.err = billing.ErrNoProviderSubscription
	if code := billingRequest(cancel, "/api/billing/subscription/cancel", ""); code != http.StatusConflict {
		t.Fatalf("unmanaged cancel: %d", code)
	}
	for err, want := range map[error]int{
		billing.ErrSubscriptionPending:  http.StatusConflict,
		billing.ErrProviderSubscription: http.StatusConflict,
		billing.ErrNotFreePlan:          http.StatusBadRequest,
	} {
		manager.err = err
		if code := billingRequest(change, "/api/billing/subscription/change", `{"planId":"FREE"}`); code != want {
			t.Errorf("change with %v: %d, want %d", err, code, want)
		}
	}
}

// A downgrade below what the partner holds answers 409 with the list to
// remove, and the preview returns the same list.
func TestBillingHandlerOverTargetLimit(t *testing.T) {
	overages := []port.QuotaOverage{{Resource: "MAX_LOCATIONS", Caption: "Locations", Count: 3, Limit: 1}}
	manager := &fakeManager{err: &billing.OverTargetLimitError{PlanID: "STANDARD", Overages: overages}}
	db := grantDB{actions: map[string]bool{"CHANGE": true}}
	h := &BillingHandler{AbstractHandler: AbstractHandler{UserService: intentUsers{}}, DB: db, Subscriptions: manager}
	routes := h.Routes()

	code, body := billingCall(routes["/api/billing/subscription/change"], "/api/billing/subscription/change", `{"planId":"STANDARD"}`)
	var problem common.ProblemDetail
	if err := json.Unmarshal([]byte(body), &problem); err != nil {
		t.Fatal(err)
	}
	if code != http.StatusConflict || problem.Status != http.StatusConflict ||
		!strings.Contains(body, `"details":[{"resource":"MAX_LOCATIONS","caption":"Locations","count":3,"limit":1}]`) {
		t.Fatalf("status=%d body=%s", code, body)
	}

	manager.err, manager.overages = nil, overages
	code, body = billingCall(routes["/api/billing/subscription/change/check"], "/api/billing/subscription/change/check", `{"planId":"STANDARD"}`)
	if code != http.StatusOK || manager.planID != "STANDARD" || !strings.Contains(body, `"overages":[{"resource":"MAX_LOCATIONS"`) {
		t.Fatalf("check: status=%d body=%s", code, body)
	}
	manager.overages = nil
	if code, body = billingCall(routes["/api/billing/subscription/change/check"], "/api/billing/subscription/change/check", `{"planId":"PRO"}`); code != http.StatusOK || !strings.Contains(body, `"overages":[]`) {
		t.Fatalf("allowed check: status=%d body=%s", code, body)
	}
	if code := billingRequest(routes["/api/billing/subscription/change/check"], "/api/billing/subscription/change/check", `{}`); code != http.StatusBadRequest {
		t.Fatalf("missing planId: %d", code)
	}
}

func TestBillingHandlerRequiresSubscriptionGrant(t *testing.T) {
	manager := &fakeManager{}
	h := &BillingHandler{AbstractHandler: AbstractHandler{UserService: intentUsers{}}, DB: grantDB{}, Subscriptions: manager}
	for path, body := range map[string]string{
		"/api/billing/subscription/cancel":       "",
		"/api/billing/subscription/change":       `{"planId":"PRO"}`,
		"/api/billing/subscription/change/check": `{"planId":"PRO"}`,
		"/api/billing/portal":                    "",
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
