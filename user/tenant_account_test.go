package user

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nauticana/keel/port"
)

func TestCreateTenantAccountTx(t *testing.T) {
	store := newMemStore()
	svc := newLocalUserService(t, store)
	ctx := context.Background()
	id := ExternalIdentity{Provider: "sso", Issuer: "https://login.acme.example", Subject: "oid-1", Email: " Ada@Acme.example ", FirstName: "Ada"}

	session, err := svc.CreateTenantAccountTx(ctx, store, 42, id)
	if err != nil {
		t.Fatal(err)
	}
	a := store.accounts[session.Id]
	if session.PartnerId != 42 || session.Email != "ada@acme.example" || a == nil || a.email != "ada@acme.example" ||
		a.verifiedBy != EmailVerifiedByTenant || store.links["https://login.acme.example|oid-1"] != session.Id {
		t.Fatalf("session %+v account %+v links %v", session, a, store.links)
	}
	if store.count(qAddPartnerUser) != 1 || store.commits != 0 {
		t.Fatalf("membership writes %d, commits %d; the caller owns the commit", store.count(qAddPartnerUser), store.commits)
	}

	for name, other := range map[string]ExternalIdentity{
		"linked identity":     id,
		"email of an account": {Provider: "sso", Issuer: "https://login.acme.example", Subject: "oid-2", Email: "ada@acme.example"},
	} {
		if _, err := svc.CreateTenantAccountTx(ctx, store, 42, other); !errors.Is(err, ErrAccountExists) {
			t.Errorf("%s: err = %v, want ErrAccountExists", name, err)
		}
	}
	for name, call := range map[string]func() error{
		"no email": func() error {
			_, err := svc.CreateTenantAccountTx(ctx, store, 42, ExternalIdentity{Provider: "sso", Issuer: "i", Subject: "s"})
			return err
		},
		"no partner": func() error {
			_, err := svc.CreateTenantAccountTx(ctx, store, 0, ExternalIdentity{Provider: "sso", Issuer: "i", Subject: "s", Email: "a@b.example"})
			return err
		},
		"no catalog": func() error {
			_, err := svc.CreateTenantAccountTx(ctx, struct{ port.TxQueryService }{store}, 42, ExternalIdentity{Provider: "sso", Issuer: "i", Subject: "s", Email: "a@b.example"})
			return err
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestJoinPartnerTx(t *testing.T) {
	store := newMemStore(5)
	svc := newLocalUserService(t, store)
	ctx := context.Background()
	if err := svc.JoinPartnerTx(ctx, store, 42, 5); err != nil || store.count(qAddPartnerUser) != 1 {
		t.Fatalf("join: %v", err)
	}
	store.failQuery[qAddPartnerUser] = &pgconn.PgError{Code: "23P01"}
	if err := svc.JoinPartnerTx(ctx, store, 42, 5); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("overlapping membership: %v", err)
	}
	if err := svc.JoinPartnerTx(ctx, store, 0, 5); !errors.Is(err, ErrNoMembership) {
		t.Fatalf("no partner: %v", err)
	}
}
