package rest

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// permissionQuery answers only the query names it was registered with, so a
// GetPermission that asks for a name the service never registered fails here
// instead of at runtime.
type permissionQuery struct {
	port.QueryService
	registered map[string]string
	asked      string
	args       []any
}

func (q *permissionQuery) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	if _, ok := q.registered[name]; !ok {
		return nil, errors.New("query " + name + " is not registered")
	}
	if name != data.DefaultGrantCatalog.ReadQuery(model.PrincipalUser) {
		return &model.QueryResult{}, nil // Init's own lookups
	}
	q.asked, q.args = name, args
	return &model.QueryResult{Rows: [][]any{{"TABLE", "SELECT", "user_account", ""}}}, nil
}

// initDB hands Init a query service and records the query map Init registered,
// so a test can assert on what the service will actually be able to ask for.
type initDB struct {
	port.DatabaseRepository
	qs     *permissionQuery
	grants port.GrantCatalog
}

func (d initDB) GetQueryService(_ context.Context, queries map[string]string) port.QueryService {
	d.qs.registered = queries
	return d.qs
}

func (d initDB) GetTableDefinitions() map[string]*model.TableDefinition { return nil }

func (d initDB) Grants() port.GrantCatalog { return d.grants }

// newPermissionService runs the real Init, so the query map under test is the
// one production builds — a grant query the service never registers fails here.
func newPermissionService(t *testing.T) (*RestService, *permissionQuery) {
	t.Helper()
	qs := &permissionQuery{}
	svc := &RestService{Journal: &auditLogger{}}
	if _, _, err := svc.Init(context.Background(), initDB{qs: qs}); err != nil {
		t.Fatalf("init: %v", err)
	}
	return svc, qs
}

func TestGetPermission_UsesRegisteredQueryForKind(t *testing.T) {
	svc, qs := newPermissionService(t)

	perms, err := svc.GetPermission(context.Background(), model.UserPrincipal(7))
	if err != nil {
		t.Fatalf("GetPermission: %v", err)
	}
	if want := data.DefaultGrantCatalog.ReadQuery(model.PrincipalUser); qs.asked != want {
		t.Errorf("queried %q, want %q", qs.asked, want)
	}
	if len(qs.args) != 1 || qs.args[0] != 7 {
		t.Errorf("args = %v, want [7]", qs.args)
	}
	if len(perms) != 1 || perms[0].ObjectName != "TABLE" || perms[0].Low != "user_account" {
		t.Errorf("unexpected permissions %+v", perms)
	}
}

func TestGetPermission_UnregisteredKindFailsLoudly(t *testing.T) {
	svc, _ := newPermissionService(t)

	if _, err := svc.GetPermission(context.Background(), model.Principal{Kind: "ghost", ID: "x"}); err == nil {
		t.Fatal("expected an error for an unregistered principal kind")
	}
	if _, err := svc.GetPermission(context.Background(), model.Principal{}); err == nil {
		t.Fatal("expected an error for the zero principal")
	}
}

func TestInit_UsesRepositoryGrantCatalog(t *testing.T) {
	grants := data.NewGrantCatalog()
	if err := grants.Register("agent", data.GrantSource{Table: "agent_permission", Subject: "agent_id"}); err != nil {
		t.Fatal(err)
	}
	qs := &permissionQuery{}
	svc := &RestService{Journal: &auditLogger{}}
	if _, _, err := svc.Init(context.Background(), initDB{qs: qs, grants: grants}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if svc.GrantCatalog != grants {
		t.Fatal("repository grant catalog was not inherited")
	}
	if _, ok := qs.registered[grants.ReadQuery("agent")]; !ok {
		t.Fatal("agent grant query was not registered")
	}
}
