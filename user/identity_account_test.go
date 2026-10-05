package user

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/port"
)

func TestCreateIdentityAccountTx(t *testing.T) {
	store := newMemStore()
	svc := newLocalUserService(t, store)
	ctx := context.Background()
	id := ExternalIdentity{Provider: "google", Issuer: GoogleIssuer, Subject: "s1", Email: "New@Corp.example", EmailVerified: true, FirstName: "N"}

	session, err := svc.CreateIdentityAccountTx(ctx, store, id)
	if err != nil {
		t.Fatal(err)
	}
	a := store.accounts[session.Id]
	if session.Email != "new@corp.example" || a == nil || a.verifiedBy != EmailVerifiedByGoogle || store.links[GoogleIssuer+"|s1"] != session.Id {
		t.Fatalf("session %+v account %+v links %v", session, a, store.links)
	}
	if store.commits != 0 {
		t.Fatal("the caller owns the commit")
	}

	for name, other := range map[string]ExternalIdentity{
		"linked identity":               id,
		"email of an account":           {Provider: "google", Issuer: GoogleIssuer, Subject: "s2", Email: "new@corp.example", EmailVerified: true},
		"untrusted email of an account": {Provider: "oidc", Issuer: "https://idp.example", Subject: "s3", Email: "new@corp.example"},
	} {
		if _, err := svc.CreateIdentityAccountTx(ctx, store, other); !errors.Is(err, ErrAccountExists) {
			t.Errorf("%s: err = %v, want ErrAccountExists", name, err)
		}
	}

	noCatalog := struct{ port.TxQueryService }{store}
	if _, err := svc.CreateIdentityAccountTx(ctx, noCatalog, ExternalIdentity{Provider: "google", Issuer: GoogleIssuer, Subject: "s4"}); err == nil {
		t.Fatal("a transaction that cannot bind the user catalog must be refused")
	}
}
