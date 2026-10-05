package user

import (
	"errors"
	"testing"
)

func google(sub, email string) ExternalIdentity {
	return ExternalIdentity{Provider: "google", Issuer: "https://accounts.google.com", Subject: sub, Email: email, EmailVerified: true}
}

func tenant(sub, email string) ExternalIdentity {
	return ExternalIdentity{Provider: "oidc", Issuer: "https://login.tenant.example", Subject: sub, Email: email, EmailVerified: true}
}

func TestEmailTrust(t *testing.T) {
	apple := func(email string, verified bool) ExternalIdentity {
		return ExternalIdentity{Provider: "apple", Issuer: AppleIssuer, Subject: "1", Email: email, EmailVerified: verified}
	}
	cases := []struct {
		id            ExternalIdentity
		trusted, link bool
	}{
		{google("1", "Rider@Gmail.com"), true, true},
		{google("1", "a@acme.com"), true, true},
		{apple("a@gmail.com", true), true, true},
		{apple("x@privaterelay.appleid.com", true), true, false},
		{apple("a@icloud.com", false), false, false},
		{google("1", ""), false, false},
		{tenant("1", "a@gmail.com"), false, false},
		{ExternalIdentity{Provider: "google", Issuer: "https://login.tenant.example", Subject: "1", Email: "a@gmail.com", EmailVerified: true}, false, false},
	}
	for _, c := range cases {
		if c.id.emailTrusted() != c.trusted || c.id.linksByEmail() != c.link {
			t.Errorf("%+v trusted = %v link = %v, want %v %v", c.id, c.id.emailTrusted(), c.id.linksByEmail(), c.trusted, c.link)
		}
	}
}

// A rider who registered with an email signs in with Google or Apple later and
// lands in the same account; a new rider is created with the verified email.
func TestVerifiedEmailLinksExistingAccount(t *testing.T) {
	store := newMemStore()
	store.addAccount(5, "rider@gmail.com", UserStatusActive)
	store.addAccount(6, "owner@acme.com", UserStatusActive)
	svc := newLocalUserService(t, store)

	session, created, err := svc.GetOrCreateUserFromSocial(google("g-5", "Rider@Gmail.com"), nil)
	if err != nil || created || session.Id != 5 || store.links[GoogleIssuer+"|g-5"] != 5 {
		t.Fatalf("existing rider = %+v, %v, %v", session, created, err)
	}
	if session, created, err = svc.GetOrCreateUserFromSocial(google("g-5", "renamed@gmail.com"), nil); err != nil || created || session.Id != 5 {
		t.Fatalf("returning rider signs in by link = %+v, %v, %v", session, created, err)
	}
	apple := ExternalIdentity{Provider: "apple", Issuer: AppleIssuer, Subject: "a-6", Email: "owner@acme.com", EmailVerified: true}
	if session, err = svc.GetUserFromExternal(apple); err != nil || session.Id != 6 {
		t.Fatalf("Apple-verified email = %+v, %v", session, err)
	}

	session, created, err = svc.GetOrCreateUserFromSocial(google("g-new", "new.rider@yahoo.com"), nil)
	if err != nil || !created || store.accounts[session.Id].email != "new.rider@yahoo.com" {
		t.Fatalf("new rider = %+v, %v, %v", session, created, err)
	}
}

func TestUntrustedEmailDoesNotTakeOverAccount(t *testing.T) {
	store := newMemStore()
	store.addAccount(5, "ceo@acme.com", UserStatusActive)
	svc := newLocalUserService(t, store)

	unverified := google("attacker", "ceo@acme.com")
	unverified.EmailVerified = false
	spoofed := tenant("attacker", "ceo@acme.com")
	spoofed.Provider = "google"
	for _, id := range []ExternalIdentity{tenant("attacker", "ceo@acme.com"), spoofed, unverified} {
		if _, _, err := svc.GetOrCreateUserFromSocial(id, nil); !errors.Is(err, ErrIdentityNotLinked) {
			t.Fatalf("%+v with another account's email: %v", id, err)
		}
		if _, err := svc.GetUserFromExternal(id); !errors.Is(err, ErrIdentityNotLinked) {
			t.Fatalf("%+v sign-in: %v", id, err)
		}
	}
	if len(store.links) != 0 || len(store.accounts) != 1 {
		t.Fatalf("refused sign-in wrote links %v accounts %d", store.links, len(store.accounts))
	}

	session, created, err := svc.GetOrCreateUserFromSocial(tenant("t-1", "new@other.com"), nil)
	if err != nil || !created || store.accounts[session.Id].email != "" {
		t.Fatalf("untrusted issuer must not reserve an email: %+v, %v, %v", session, created, err)
	}
}

func TestLinkExternalIdentity(t *testing.T) {
	store := newMemStore()
	store.addAccount(5, "ceo@acme.com", UserStatusActive)
	store.addAccount(6, "other@acme.com", UserStatusActive)
	svc := newLocalUserService(t, store)
	apple := ExternalIdentity{Provider: "apple", Issuer: "https://appleid.apple.com", Subject: "a-5", Email: "ceo@acme.com", EmailVerified: true}

	if err := svc.LinkExternalIdentity(5, apple); err != nil {
		t.Fatal(err)
	}
	if err := svc.LinkExternalIdentity(5, apple); err != nil {
		t.Fatalf("relinking the same identity: %v", err)
	}
	if session, err := svc.GetUserFromExternal(apple); err != nil || session.Id != 5 {
		t.Fatalf("linked identity signs in = %+v, %v", session, err)
	}
	if err := svc.LinkExternalIdentity(6, apple); !errors.Is(err, ErrIdentityLinked) {
		t.Fatalf("identity of another account: %v", err)
	}
	if err := svc.LinkExternalIdentity(5, ExternalIdentity{Provider: "apple", Issuer: apple.Issuer, Subject: "a-other"}); !errors.Is(err, ErrIdentityLinked) {
		t.Fatalf("second identity from the same issuer: %v", err)
	}
	otherIssuer := ExternalIdentity{Provider: "oidc", Issuer: "https://login.example.net", Subject: apple.Subject}
	if err := svc.LinkExternalIdentity(5, otherIssuer); err != nil {
		t.Fatalf("same subject under another issuer: %v", err)
	}
	if session, err := svc.GetUserFromExternal(otherIssuer); err != nil || session.Id != 5 {
		t.Fatalf("issuer-keyed identity signs in = %+v, %v", session, err)
	}
	if err := svc.LinkExternalIdentity(5, ExternalIdentity{Provider: "phone", Issuer: "https://phone.invalid", Subject: "x"}); err == nil {
		t.Fatal("phone is not an external identity")
	}
}

func TestExternalSignInChecksAccountStatus(t *testing.T) {
	store := newMemStore()
	store.addAccount(5, "a@gmail.com", UserStatusAdminLock)
	store.links["https://accounts.google.com|g-5"] = 5
	svc := newLocalUserService(t, store)
	if _, _, err := svc.GetOrCreateUserFromSocial(google("g-5", "a@gmail.com"), nil); !errors.Is(err, ErrAccountUnavailable) {
		t.Fatalf("locked linked account: %v", err)
	}
	store.addAccount(6, "b@gmail.com", UserStatusExpired)
	if _, _, err := svc.GetOrCreateUserFromSocial(google("g-6", "b@gmail.com"), nil); !errors.Is(err, ErrAccountUnavailable) {
		t.Fatalf("expired account by email: %v", err)
	}
	if len(store.accounts) != 2 {
		t.Fatal("an unavailable account must not cause a new account")
	}
}

func TestExternalSignInFailsClosedOnLookupError(t *testing.T) {
	store := newMemStore()
	store.failQuery[qUserByExternalIdentity] = errDatabaseDown
	svc := newLocalUserService(t, store)
	if _, _, err := svc.GetOrCreateUserFromSocial(google("g-1", "a@gmail.com"), nil); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("lookup error: %v", err)
	}
	if store.count(qCreateSocialUser) != 0 {
		t.Fatal("a failed link lookup must not create an account")
	}
}

func TestUnverifiedEmailIsNotStored(t *testing.T) {
	store := newMemStore()
	svc := newLocalUserService(t, store)
	session, created, err := svc.GetOrCreateUserFromSocial(ExternalIdentity{Provider: "apple", Issuer: "https://appleid.apple.com", Subject: "a-1", Email: "victim@acme.com"}, nil)
	if err != nil || !created || store.accounts[session.Id].email != "" {
		t.Fatalf("unverified email = %+v, %v, %v", session, created, err)
	}
	if _, _, err := svc.GetOrCreateUserFromSocial(ExternalIdentity{Provider: "apple", Issuer: "https://appleid.apple.com"}, nil); err == nil {
		t.Fatal("an identity without a subject must be refused")
	}
}
