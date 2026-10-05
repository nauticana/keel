package user

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// holderRepo answers domain.Service.IdentityHolder: which partners hold a
// domain by identity-grade evidence.
type holderRepo struct {
	port.DatabaseRepository
	holders map[string][]int64
	err     error
}

func (r holderRepo) GetQueryService(context.Context, map[string]string) port.QueryService { return r }
func (r holderRepo) GenID() int64                                                         { return 0 }
func (r holderRepo) Query(_ context.Context, _ string, args ...any) (*model.QueryResult, error) {
	if r.err != nil {
		return nil, r.err
	}
	out := &model.QueryResult{}
	for _, partner := range r.holders[args[0].(string)] {
		out.Rows = append(out.Rows, []any{partner})
	}
	return out, nil
}

// Only a Google Workspace account on a domain the user's partner holds counts
// as the partner's own identity provider.
func TestExternalSignInMethodProvesThePartnerIdP(t *testing.T) {
	repo := holderRepo{holders: map[string][]int64{"acme.com": {11}, "shared.com": {11, 12}}}
	svc := newLocalUserService(t, newMemStore())
	svc.TenantDomains = &domain.Service{DB: repo}
	workspace := func(hd string) ExternalIdentity {
		id := google("g-1", "a@"+hd)
		id.HostedDomain = hd
		return id
	}
	cases := []struct {
		name    string
		partner int64
		id      ExternalIdentity
		want    string
	}{
		{"partner's Workspace domain", 11, workspace("acme.com"), SignInTenant},
		{"upper-case hosted domain", 11, workspace("ACME.com"), SignInTenant},
		{"another partner's domain", 12, workspace("acme.com"), SignInExternal},
		{"domain nobody holds", 11, workspace("other.com"), SignInExternal},
		{"domain with two holders", 11, workspace("shared.com"), SignInExternal},
		{"personal Google account", 11, google("g-2", "a@gmail.com"), SignInExternal},
		{"user without a partner", 0, workspace("acme.com"), SignInExternal},
		{"Apple", 11, ExternalIdentity{Provider: "apple", Issuer: AppleIssuer, Subject: "a-1", HostedDomain: "acme.com"}, SignInExternal},
		{"another issuer claiming a hosted domain", 11, ExternalIdentity{Provider: "google", Issuer: "https://login.tenant.example", Subject: "x", HostedDomain: "acme.com"}, SignInExternal},
	}
	for _, c := range cases {
		if got, err := svc.ExternalSignInMethod(c.partner, c.id); err != nil || got != c.want {
			t.Errorf("%s = %q, %v, want %q", c.name, got, err, c.want)
		}
	}

	svc.TenantDomains = &domain.Service{DB: holderRepo{err: errDatabaseDown}}
	if _, err := svc.ExternalSignInMethod(11, workspace("acme.com")); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("a failed lookup must not classify the sign-in: %v", err)
	}
	svc.TenantDomains = nil
	if got, err := svc.ExternalSignInMethod(11, workspace("acme.com")); err != nil || got != SignInExternal {
		t.Fatalf("without TenantDomains nothing is proven: %q, %v", got, err)
	}
	if _, err := svc.ExternalSignInMethod(11, ExternalIdentity{Provider: "google"}); err == nil {
		t.Fatal("an identity without issuer and subject must be refused")
	}
}
