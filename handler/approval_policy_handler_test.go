package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/approval"
	"github.com/nauticana/keel/model"
)

type fakeApprovalPolicies struct {
	set       approval.Policy
	confirmed [3]any
	err       error
}

func (f *fakeApprovalPolicies) SetPolicy(_ context.Context, p approval.Policy) (bool, error) {
	f.set = p
	return !p.AllowSinglePerson, f.err
}

func (f *fakeApprovalPolicies) ConfirmPolicy(_ context.Context, partnerID int64, objectType string, confirmerID int64) error {
	f.confirmed = [3]any{partnerID, objectType, confirmerID}
	return f.err
}

func TestApprovalPolicyUsesTheSessionPartner(t *testing.T) {
	policies := &fakeApprovalPolicies{}
	h := &ApprovalPolicyHandler{Policies: policies}
	call := func(fn JSONFunc, body string, session *model.UserSession) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/approval_policy/set", strings.NewReader(body))
		if session != nil {
			stashSession(r, session)
		}
		w := httptest.NewRecorder()
		h.JSON(http.MethodPost, fn)(w, r)
		return w
	}
	admin := &model.UserSession{Id: 3, PartnerId: 7}
	w := call(h.Set, `{"objectType":"driver","allowSinglePerson":true,"partnerId":99}`, admin)
	if w.Code != http.StatusOK || policies.set != (approval.Policy{PartnerID: 7, ObjectType: "driver", AllowSinglePerson: true, ChangedBy: 3}) ||
		!strings.Contains(w.Body.String(), `"inForce":false`) {
		t.Fatalf("set = %d %s, service saw %+v", w.Code, w.Body, policies.set)
	}
	if w := call(h.Confirm, `{"objectType":"driver"}`, admin); w.Code != http.StatusOK || policies.confirmed != [3]any{int64(7), "driver", int64(3)} {
		t.Fatalf("confirm = %d, service saw %v", w.Code, policies.confirmed)
	}
	for body, want := range map[string]int{`{}`: http.StatusBadRequest, `[]`: http.StatusBadRequest} {
		if w := call(h.Set, body, admin); w.Code != want {
			t.Errorf("%s = %d, want %d", body, w.Code, want)
		}
	}
	if w := call(h.Set, `{"objectType":"driver"}`, &model.UserSession{Id: 3}); w.Code != http.StatusUnauthorized {
		t.Fatalf("no partner = %d", w.Code)
	}
	for err, want := range map[error]int{approval.ErrNotAdministrator: http.StatusForbidden, approval.ErrPolicyConfirmation: http.StatusForbidden,
		approval.ErrNoPendingPolicy: http.StatusConflict, model.NewBadRequest("too long"): http.StatusBadRequest} {
		policies.err = err
		if w := call(h.Confirm, `{"objectType":"driver"}`, admin); w.Code != want {
			t.Errorf("%v = %d, want %d", err, w.Code, want)
		}
	}
	route := h.Routes("/api/v1")["/api/v1/approval_policy/confirm"]
	rec := httptest.NewRecorder()
	route(rec, httptest.NewRequest(http.MethodPost, "/api/v1/approval_policy/confirm", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("route without a session = %d", rec.Code)
	}
}
