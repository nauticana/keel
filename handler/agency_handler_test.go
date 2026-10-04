package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type fakeDelegationAgency struct {
	port.AgencyService
	client, caller, user int64
	grants               []model.AgencyRoleGrant
	err                  error
}

func (f *fakeDelegationAgency) SetDelegationRoles(_ context.Context, client, caller int64, grants []model.AgencyRoleGrant, user int64) error {
	f.client, f.caller, f.grants, f.user = client, caller, grants, user
	return f.err
}

func delegationRoleRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agency/delegation/roles", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	stashSession(r, &model.UserSession{Id: 3, PartnerId: 7})
	return r
}

func TestAgencyHandlerSetDelegationRole(t *testing.T) {
	agency := &fakeDelegationAgency{}
	h := &AgencyHandler{Agency: agency}

	w := httptest.NewRecorder()
	h.SetDelegationRoles(w, delegationRoleRequest(`{"roles":[{"role":"operate","expiresAt":"2030-01-02T03:04:05Z"},{"role":"view"}]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d %s", w.Code, w.Body.String())
	}
	if agency.client != 7 || agency.caller != 7 || agency.user != 3 || len(agency.grants) != 2 ||
		agency.grants[0].Role != "operate" || agency.grants[0].ExpiresAt == nil || agency.grants[0].ExpiresAt.Year() != 2030 ||
		agency.grants[1].ExpiresAt != nil {
		t.Fatalf("service call = %+v", agency)
	}

	w = httptest.NewRecorder()
	h.SetDelegationRoles(w, delegationRoleRequest(`{"clientPartnerId":9,"roles":[]}`))
	if agency.client != 9 || agency.caller != 7 {
		t.Fatalf("explicit client must reach the service ownership check: %+v", agency)
	}

	w = httptest.NewRecorder()
	h.SetDelegationRoles(w, delegationRoleRequest(`{"roles":[{"role":"publish","grantedBy":1}]}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d, want 400", w.Code)
	}

	for err, want := range map[error]int{
		port.ErrNotClientOwner:          http.StatusForbidden,
		port.ErrInvalidDelegationRole:   http.StatusUnprocessableEntity,
		port.ErrDuplicateDelegationRole: http.StatusUnprocessableEntity,
		port.ErrTooManyDelegationRoles:  http.StatusUnprocessableEntity,
		port.ErrDelegationExpiryPast:    http.StatusUnprocessableEntity,
		port.ErrAgencyNotFound:          http.StatusNotFound,
	} {
		agency.err = err
		w = httptest.NewRecorder()
		h.SetDelegationRoles(w, delegationRoleRequest(`{"roles":[{"role":"view"}]}`))
		if w.Code != want {
			t.Errorf("%v: status = %d, want %d", err, w.Code, want)
		}
	}
}

func TestAgencyHandlerDelegationRoleRequiresGrant(t *testing.T) {
	h := &AgencyHandler{Agency: &fakeDelegationAgency{}, DB: denyAllRepo{}}
	route := h.Routes("/api/v1", "/public")["/api/v1/agency/delegation/roles"]
	if route == nil {
		t.Fatal("delegation role route not mounted")
	}
	w := httptest.NewRecorder()
	route(w, delegationRoleRequest(`{"roles":[{"role":"view"}]}`))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without AGENCY_DELEGATION/SET_ROLE", w.Code)
	}
}

type denyAllRepo struct{ port.DatabaseRepository }

func (denyAllRepo) CheckActionPermission(context.Context, model.Principal, string, string, string) (bool, bool) {
	return false, false
}
