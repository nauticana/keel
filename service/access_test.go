package service

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/keeltest"
	"github.com/nauticana/keel/model"
)

func TestAccessTable(t *testing.T) {
	db := keeltest.NewDatabase("TABLE/UPDATE/widget")
	access := Access{DB: db}
	if _, err := access.Table(keeltest.AsUser(7, 3), 7, "UPDATE", "widget"); err != nil {
		t.Fatalf("granted caller refused: %v", err)
	}
	if _, err := access.Table(keeltest.AsUser(7, 3), 7, "DELETE", "widget"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ungranted action: %v, want ErrForbidden", err)
	}
	if _, err := access.Table(keeltest.AsUser(7, 3), 8, "UPDATE", "widget"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other tenant: %v, want ErrNotFound", err)
	}
	if _, err := access.Table(keeltest.AsUser(7, 3), 0, "UPDATE", "widget"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no tenant: %v, want ErrNotFound", err)
	}
	if got := db.As[0]; got.Kind != model.PrincipalUser || got.ID != 3 {
		t.Fatalf("principal = %+v, want user 3", got)
	}
}

func TestAccessRefusesUnauthenticatedAndNoRepository(t *testing.T) {
	if _, err := (Access{DB: keeltest.NewDatabase()}).Tenant(context.Background(), 7); !errors.Is(err, common.ErrUnauthenticated) {
		t.Fatalf("no caller: %v, want ErrUnauthenticated", err)
	}
	if _, err := (Access{}).Platform(keeltest.AsUser(7, 3), "TABLE", "SELECT", "widget"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("no repository: %v, want ErrForbidden", err)
	}
}

func TestAccessWorkerRoleOnlyWithoutCaller(t *testing.T) {
	db := keeltest.NewDatabase("TABLE/SELECT/widget")
	worker := Access{DB: db, Role: "WORKER"}
	if _, err := worker.Table(context.Background(), 9, "SELECT", "widget"); err != nil {
		t.Fatalf("worker refused: %v", err)
	}
	if got := db.As[0]; got.Kind != model.PrincipalRole || got.ID != "WORKER" {
		t.Fatalf("principal = %+v, want the worker role", got)
	}
	apiKeyOnly := common.WithCallerSession(context.Background(), common.CallerSession{PartnerID: 9, APIKeyID: 4})
	if _, err := worker.Table(apiKeyOnly, 9, "SELECT", "widget"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a bound caller without a user took the worker role: %v", err)
	}
}
