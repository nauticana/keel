package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/model"
)

func domainRequest(method, body string, session *model.UserSession) *http.Request {
	r := httptest.NewRequest(method, "/api/v1/partner_domain/challenge", strings.NewReader(body))
	if session != nil {
		stashSession(r, session)
	}
	return r
}

func TestDomainVerificationHandlerBridge(t *testing.T) {
	member := &model.UserSession{Id: 3, PartnerId: 7}
	svc := &domain.Service{Verifiers: nil}
	cases := []struct {
		name    string
		h       *DomainVerificationHandler
		req     *http.Request
		want    int
		problem string
	}{
		{"get", &DomainVerificationHandler{Domains: svc}, domainRequest(http.MethodGet, "", member), http.StatusMethodNotAllowed, ""},
		{"unconfigured", &DomainVerificationHandler{}, domainRequest(http.MethodPost, `{"domainUrl":"example.com","method":"DT"}`, member), http.StatusServiceUnavailable, ""},
		{"no session", &DomainVerificationHandler{Domains: svc}, domainRequest(http.MethodPost, `{"domainUrl":"example.com","method":"DT"}`, nil), http.StatusUnauthorized, ""},
		{"no partner", &DomainVerificationHandler{Domains: svc}, domainRequest(http.MethodPost, `{"domainUrl":"example.com","method":"DT"}`, &model.UserSession{Id: 3}), http.StatusUnauthorized, ""},
		{"no domain", &DomainVerificationHandler{Domains: svc}, domainRequest(http.MethodPost, `{"method":"DT"}`, member), http.StatusBadRequest, ""},
		{"email code without sender", &DomainVerificationHandler{Domains: svc}, domainRequest(http.MethodPost, `{"domainUrl":"example.com","method":"EC","recipient":"a@example.com"}`, member), http.StatusUnprocessableEntity, "domain_method_unsupported"},
		{"unwired method", &DomainVerificationHandler{Domains: svc}, domainRequest(http.MethodPost, `{"domainUrl":"example.com","method":"DT"}`, member), http.StatusUnprocessableEntity, "domain_method_unsupported"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c.h.Challenge(w, c.req)
			if w.Code != c.want || !strings.Contains(w.Body.String(), c.problem) {
				t.Fatalf("status = %d %s, want %d %s", w.Code, w.Body.String(), c.want, c.problem)
			}
		})
	}
}

func TestDomainVerificationRoutesAreGated(t *testing.T) {
	routes := (&DomainVerificationHandler{}).Routes("/api/v1")
	for _, path := range []string{"/api/v1/partner_domain/challenge", "/api/v1/partner_domain/confirm", "/api/v1/partner_domain/unverify"} {
		route, ok := routes[path]
		if !ok {
			t.Fatalf("route %s missing", path)
		}
		w := httptest.NewRecorder()
		route(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s without a session = %d", path, w.Code)
		}
	}
}
