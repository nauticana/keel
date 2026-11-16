package user

import (
	"context"
	"errors"
	"testing"
	"time"

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
	if err := svc.JoinPartnerTx(ctx, store, 42, 5, nil, nil); err != nil || len(store.joins) != 1 {
		t.Fatalf("join: %v", err)
	}
	if got := store.joins[0]; got[2] != nil || got[3] != nil {
		t.Fatalf("an undated join must leave begda to the database and endda open: %v", got)
	}

	local := time.FixedZone("UTC+3", 3*3600)
	begda := time.Now().Add(24 * time.Hour).In(local)
	endda := begda.Add(30 * 24 * time.Hour)
	if err := svc.JoinPartnerTx(ctx, store, 42, 5, &begda, &endda); err != nil {
		t.Fatalf("dated join: %v", err)
	}
	if got := store.joins[1]; got[2] != begda.UTC() || got[3] != endda.UTC() {
		t.Fatalf("dated join args %v, want begda %v and endda %v in UTC", got, begda.UTC(), endda.UTC())
	}
	if err := svc.JoinPartnerTx(ctx, store, 42, 5, nil, &endda); err != nil || store.joins[2][2] != nil {
		t.Fatalf("open start, fixed end: %v %v", err, store.joins[2])
	}

	past := time.Now().Add(-time.Hour)
	for name, period := range map[string][2]*time.Time{
		"end before begin": {&endda, &begda},
		"end at begin":     {&begda, &begda},
		"end before now":   {nil, &past},
	} {
		if err := svc.JoinPartnerTx(ctx, store, 42, 5, period[0], period[1]); !errors.Is(err, ErrInvalidMembershipPeriod) {
			t.Errorf("%s: err = %v, want ErrInvalidMembershipPeriod", name, err)
		}
	}
	if len(store.joins) != 3 {
		t.Fatalf("an invalid period must not write; writes %d", len(store.joins))
	}

	store.failQuery[qAddPartnerUser] = &pgconn.PgError{Code: "23P01"}
	if err := svc.JoinPartnerTx(ctx, store, 42, 5, &begda, nil); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("overlapping membership: %v", err)
	}
	if err := svc.JoinPartnerTx(ctx, store, 0, 5, nil, nil); !errors.Is(err, ErrNoMembership) {
		t.Fatalf("no partner: %v", err)
	}
}
