package sso

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

func TestStartRoutesOnlyHeldDomainsWithActiveConnection(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	target, key, err := f.svc.Start(ctx, " Ada@Eu.ACME.example ", callbck)
	if err != nil || key == "" || !strings.HasPrefix(target, "https://idp.example/") || !strings.Contains(target, "ada%40eu.acme.example") {
		t.Fatalf("Start(subdomain) = %q %q %v", target, key, err)
	}
	for _, email := range []string{"ada@unknown.example", "ada@other.example", "not-an-email", "ada@example"} {
		if _, _, err := f.svc.Start(ctx, email, callbck); !errors.Is(err, ErrUnavailable) {
			t.Errorf("Start(%s) = %v", email, err)
		}
	}
	f.store.connections[connID].Status = StatusDraft
	if _, _, err := f.svc.Start(ctx, "ada@acme.example", callbck); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("draft connection routed: %v", err)
	}
}

func TestSignInLinkedMemberGetsTenantSessionAndMappedRoles(t *testing.T) {
	f := newFixture(t)
	f.users.accounts[5] = &model.UserSession{Id: 5, Email: "ada@acme.example", PartnerId: acme}
	f.users.links[issuer+"|sub-1"] = 5
	f.store.mappings = [][3]string{{"groups", "admins", "PARTNER_ADMIN"}, {"groups", "admins", "SUPER"}, {"groups", "finance", "BILLING"}}
	f.store.open[5] = []string{"MANUAL"}

	out, err := f.signIn(t, "ada@acme.example")
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if out.Session.Id != 5 || out.Session.PartnerId != acme || out.Session.SignInMethod != user.SignInTenant || f.users.checkedFor[0] != user.SignInTenant {
		t.Fatalf("session = %+v, checked %v", out.Session, f.users.checkedFor)
	}
	if _, ok := f.store.grants[5]["PARTNER_ADMIN"]; !ok || len(f.store.grants[5]) != 1 {
		t.Fatalf("grants = %v; a platform role must never be granted", f.store.grants[5])
	}

	// The claim is gone: the mapped role ends, the manual one stays.
	f.provider.assertion.Claims = map[string][]string{"groups": {"staff"}}
	if _, err := f.signIn(t, "ada@acme.example"); err != nil {
		t.Fatal(err)
	}
	if len(f.store.grants[5]) != 0 || len(f.store.open[5]) != 1 || f.store.open[5][0] != "MANUAL" {
		t.Fatalf("after claim removal: grants %v, open %v", f.store.grants[5], f.store.open[5])
	}

	// A truncated claim grants nothing.
	f.provider.assertion.Claims, f.provider.assertion.Overage = map[string][]string{"groups": {"admins"}}, []string{"groups"}
	if _, err := f.signIn(t, "ada@acme.example"); err != nil || len(f.store.grants[5]) != 0 {
		t.Fatalf("overage granted %v, %v", f.store.grants[5], err)
	}
}

func TestSignInRefusals(t *testing.T) {
	cases := map[string]struct {
		setup func(f *fixture)
		want  error
	}{
		"email outside held domains": {setup: func(f *fixture) { f.provider.assertion.Email = "ada@gmail.com" }, want: ErrEmailNotAllowed},
		"email of another tenant":    {setup: func(f *fixture) { f.provider.assertion.Email = "eve@other.example" }, want: ErrEmailNotAllowed},
		"no email":                   {setup: func(f *fixture) { f.provider.assertion.Email = "" }, want: ErrEmailNotAllowed},
		"mfa required":               {setup: func(f *fixture) { f.store.connections[connID].RequireMFA = true }, want: ErrMFARequired},
		"foreign issuer":             {setup: func(f *fixture) { f.provider.assertion.Issuer = "https://evil.example" }, want: ErrSignInFailed},
		"provider refusal":           {setup: func(f *fixture) { f.provider.err = errors.New("bad nonce") }, want: ErrSignInFailed},
		"no account without jit":     {want: ErrNoAccount},
		"account of another tenant": {setup: func(f *fixture) {
			f.users.accounts[8] = &model.UserSession{Id: 8, Email: "ada@acme.example", PartnerId: 99}
		}, want: ErrOtherPartner},
		"linked account of another tenant": {setup: func(f *fixture) {
			f.users.accounts[8] = &model.UserSession{Id: 8, Email: "x@other.example", PartnerId: 99}
			f.users.links[issuer+"|sub-1"] = 8
		}, want: ErrOtherPartner},
		"partnerless account without jit": {setup: func(f *fixture) {
			f.users.accounts[8] = &model.UserSession{Id: 8, Email: "ada@acme.example"}
		}, want: ErrNoAccount},
		"google hosted domain of another tenant": {setup: func(f *fixture) {
			f.store.connections[connID].Issuer = googleIssuer
			f.provider.assertion.Issuer, f.provider.assertion.HostedDomain = googleIssuer, "other.example"
		}, want: ErrEmailNotAllowed},
		"google account without hosted domain": {setup: func(f *fixture) {
			f.store.connections[connID].Issuer = googleIssuer
			f.provider.assertion.Issuer = googleIssuer
		}, want: ErrEmailNotAllowed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			if out, err := f.signIn(t, "ada@acme.example"); !errors.Is(err, tc.want) || out != nil {
				t.Fatalf("sign-in = %+v, %v; want %v", out, err, tc.want)
			}
			if len(f.users.created) != 0 {
				t.Fatal("no account may be created")
			}
		})
	}
}

func TestSignInLinksSameTenantAccountByEmail(t *testing.T) {
	f := newFixture(t)
	f.users.accounts[6] = &model.UserSession{Id: 6, Email: "ada@acme.example", PartnerId: acme}
	out, err := f.signIn(t, "ada@acme.example")
	if err != nil || out.Session.Id != 6 || f.users.links[issuer+"|sub-1"] != 6 {
		t.Fatalf("sign-in = %+v, %v; links %v", out, err, f.users.links)
	}
}

func TestSignInCreatesAndJoinsOnlyUnderPolicy(t *testing.T) {
	f := newFixture(t)
	f.users.policies[user.PolicySSOJITCreate] = 1
	f.provider.assertion.GivenName = "Ada"
	out, err := f.signIn(t, "ada@acme.example")
	if err != nil || len(f.users.created) != 1 || out.Session.PartnerId != acme || f.store.committed == 0 {
		t.Fatalf("create = %+v, %v, created %v", out, err, f.users.created)
	}
	if id := f.users.created[0]; id.Provider != identityProvider || id.Issuer != issuer || id.Email != "ada@acme.example" || id.FirstName != "Ada" {
		t.Fatalf("created identity = %+v", id)
	}

	f2 := newFixture(t)
	f2.users.policies[user.PolicySSOJITCreate] = 1
	f2.users.accounts[8] = &model.UserSession{Id: 8, Email: "ada@acme.example"}
	if out, err := f2.signIn(t, "ada@acme.example"); err != nil || out.Session.Id != 8 || len(f2.users.joined) != 1 {
		t.Fatalf("join = %+v, %v", out, err)
	}
}

func TestCompleteIsSingleUseAndNeedsActiveConnection(t *testing.T) {
	f := newFixture(t)
	f.users.accounts[5] = &model.UserSession{Id: 5, Email: "ada@acme.example", PartnerId: acme}
	f.users.links[issuer+"|sub-1"] = 5
	ctx := context.Background()
	_, key, err := f.svc.Start(ctx, "ada@acme.example", callbck)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Complete(ctx, key, callbck, url.Values{}); err != nil {
		t.Fatalf("first completion: %v", err)
	}
	if _, err := f.svc.Complete(ctx, key, callbck, url.Values{}); !errors.Is(err, ErrSignInFailed) {
		t.Fatalf("replay = %v", err)
	}
	if _, err := f.svc.Complete(ctx, "", callbck, url.Values{}); !errors.Is(err, ErrSignInFailed) {
		t.Fatalf("no cookie = %v", err)
	}
	_, key, _ = f.svc.Start(ctx, "ada@acme.example", callbck)
	f.store.connections[connID].Status = StatusDisabled
	if _, err := f.svc.Complete(ctx, key, callbck, url.Values{}); !errors.Is(err, ErrSignInFailed) {
		t.Fatalf("disabled in between = %v", err)
	}
}
