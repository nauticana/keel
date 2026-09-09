package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/secret"
	"github.com/nauticana/keel/user"
)

type publicRouteUsers struct{ user.UserService }

func (publicRouteUsers) GetPasswordPolicy() model.PasswordPolicy {
	return model.PasswordPolicy{MinPasswordLength: 12}
}

var _ user.UserService = publicRouteUsers{}

type publicRouteSecrets struct{ secret.SecretProvider }

var _ secret.SecretProvider = publicRouteSecrets{}

func TestPublicRoutesGatedByDependencies(t *testing.T) {
	bare := (&PublicHandler{AbstractHandler: AbstractHandler{UserService: publicRouteUsers{}}}).GetPublicRoutes()
	for _, path := range []string{"/public/login/gmail", "/public/register", "/public/plans", "/public/password/forgot"} {
		if _, ok := bare[path]; ok {
			t.Errorf("%s mounted without its dependency", path)
		}
	}
	full := (&PublicHandler{RegisterService: &user.RegistrationService{}, Secrets: publicRouteSecrets{}}).GetPublicRoutes()
	if len(full) != 9 {
		t.Fatalf("expected 9 routes, got %d", len(full))
	}
}

func TestPublicPasswordRoutes(t *testing.T) {
	h := &PublicHandler{AbstractHandler: AbstractHandler{UserService: publicRouteUsers{}}, RegisterService: &user.RegistrationService{}}
	mux := http.NewServeMux()
	for path, fn := range h.GetPublicRoutes() {
		if !strings.HasPrefix(path, "/public/") {
			t.Fatalf("public route under authenticated prefix: %s", path)
		}
		mux.HandleFunc(path, fn)
	}
	for _, tc := range []struct {
		path, method string
		status       int
	}{
		{"/public/password/policy", "GET", 200},
		{"/public/password/forgot", "POST", 400},
		{"/public/password/reset", "POST", 400},
		{"/public/password/forgot", "GET", 405},
		{"/public/password/reset", "GET", 405},
	} {
		t.Run(tc.path+tc.method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`)))
			if rec.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.path == "/public/password/policy" && !strings.Contains(rec.Body.String(), `"minLength":12`) {
				t.Fatalf("missing policy: %s", rec.Body.String())
			}
		})
	}
}
