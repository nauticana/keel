package common

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/model"
)

func TestCallerSessionRoundTrip(t *testing.T) {
	in := CallerSession{Principal: &model.TokenPrincipal{Subject: "sub-1", Scopes: []string{"read", "write"}}, PartnerID: 42, APIKeyID: 7, Scopes: []string{"admin"}, RequestID: "req-1"}
	out, err := CallerSessionFromContext(WithCallerSession(context.Background(), in))
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != "sub-1" || out.PartnerID != 42 || out.APIKeyID != 7 || out.RequestID != "req-1" || !out.HasScope("write") || out.HasScope("admin") {
		t.Fatalf("session = %+v", out)
	}
	if _, err := CallerSessionFromContext(context.Background()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unauthenticated = %v", err)
	}
	if s, err := CallerSessionFromContext(context.WithValue(context.Background(), ApiKeyID, int64(9))); err != nil || s.APIKeyID != 9 {
		t.Fatalf("api key alone must authenticate: %+v, %v", s, err)
	}
	principalOnly := &model.TokenPrincipal{Subject: "sub-2", Scopes: []string{"read"}}
	if s, err := CallerSessionFromContext(WithCallerSession(nil, CallerSession{Principal: principalOnly})); err != nil || s.Subject != "sub-2" || !s.HasScope("read") {
		t.Fatalf("principal defaults = %+v, %v", s, err)
	}
	conflict := context.WithValue(context.WithValue(context.Background(), AuthPrincipal, principalOnly), Subject, "sub-3")
	if _, err := CallerSessionFromContext(conflict); !errors.Is(err, ErrCallerIdentityConflict) {
		t.Fatalf("identity conflict = %v", err)
	}
	if _, err := CallerSessionFromContext(context.WithValue(context.Background(), AuthPrincipal, &model.TokenPrincipal{})); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty principal = %v", err)
	}
	broadened := context.WithValue(context.WithValue(context.Background(), AuthPrincipal, principalOnly), Scopes, "read admin")
	if s, err := CallerSessionFromContext(broadened); err != nil || s.HasScope("admin") {
		t.Fatalf("context scopes broadened token principal: %+v, %v", s, err)
	}
	if _, err := CallerSessionFromContext(nil); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil context = %v", err)
	}
}
