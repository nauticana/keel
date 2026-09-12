package data

import (
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

func TestBaseGrantCatalog_UserKindShape(t *testing.T) {
	c := NewGrantCatalog()
	q := c.Queries()

	check, ok := q[c.CheckQuery(model.PrincipalUser)]
	if !ok {
		t.Fatal("user grant query missing")
	}
	for _, want := range []string{"FROM user_permission p", "p.user_id = ?", "a.low_limit = '*'", "p.begda <= CURRENT_TIMESTAMP"} {
		if !strings.Contains(check, want) {
			t.Errorf("missing %q in:\n%s", want, check)
		}
	}
	read, ok := q[c.ReadQuery(model.PrincipalUser)]
	if !ok {
		t.Fatal("user read-authorization query missing")
	}
	if !strings.Contains(read, "FROM user_permission") || !strings.Contains(read, "user_id = ?") {
		t.Errorf("unexpected read-authorization SQL:\n%s", read)
	}
}

func TestBaseGrantCatalog_FilteredKind(t *testing.T) {
	const kind model.PrincipalKind = "agent"
	c := NewGrantCatalog()
	if err := c.Register(kind, GrantSource{Table: "agent_permission", Subject: "agent_id", Filters: []string{"tenant_id"}}); err != nil {
		t.Fatalf("register: %v", err)
	}

	sql := c.Queries()[c.CheckQuery(kind)]
	for _, want := range []string{"FROM agent_permission p", "p.agent_id = ?", "p.tenant_id = ?"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in:\n%s", want, sql)
		}
	}

	args, err := c.Args(model.Principal{Kind: kind, ID: "agent-7", Scope: []any{int64(42)}})
	if err != nil {
		t.Fatalf("args: %v", err)
	}
	if len(args) != 2 || args[0] != "agent-7" || args[1] != int64(42) {
		t.Fatalf("unexpected args %v", args)
	}

	// A principal omitting the kind's filters must fail closed, not match every tenant.
	if _, err := c.Args(model.Principal{Kind: kind, ID: "agent-7"}); err == nil {
		t.Error("expected an arity error for a principal missing its scope")
	}
}

// Registering on one catalog must not leak into another — that is the point of
// injecting it rather than reaching for a package global.
func TestBaseGrantCatalog_IsolatedPerInstance(t *testing.T) {
	registered, bare := NewGrantCatalog(), NewGrantCatalog()
	if err := registered.Register("agent", GrantSource{Table: "agent_permission", Subject: "agent_id"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := bare.Source("agent"); ok {
		t.Error("registration leaked into a second catalog")
	}
}

func TestBaseGrantCatalog_ArgsFailClosed(t *testing.T) {
	c := NewGrantCatalog()
	cases := map[string]model.Principal{
		"zero value":        {},
		"unregistered kind": {Kind: "nope", ID: 1},
		"no id":             {Kind: model.PrincipalUser},
	}
	for name, p := range cases {
		if _, err := c.Args(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestBaseGrantCatalog_RejectsUnsafeIdentifiers(t *testing.T) {
	c := NewGrantCatalog()
	cases := map[string]GrantSource{
		"table":   {Table: "agent_permission; DROP TABLE x", Subject: "agent_id"},
		"subject": {Table: "agent_permission", Subject: "agent_id) OR (1=1"},
		"filter":  {Table: "agent_permission", Subject: "agent_id", Filters: []string{"tenant_id = 1 OR 1"}},
	}
	for name, src := range cases {
		if err := c.Register("unsafe", src); err == nil {
			t.Errorf("%s: expected a rejection", name)
		}
	}
}

func TestBaseGrantCatalog_NoGlobalRolesDeniesBypass(t *testing.T) {
	c := NewGrantCatalog()
	c.GlobalRoles = nil
	if sql := c.Queries()[QCheckGlobalRole]; !strings.Contains(sql, "WHERE FALSE") {
		t.Errorf("empty role set must match nothing, got:\n%s", sql)
	}
}

var _ port.GrantCatalog = NewGrantCatalog()

// DefaultGrantCatalog is built at package init, so a boot-time append to
// GlobalRoleIDs cannot reach it — the documented escape is an explicit catalog.
func TestGlobalRoleIDs_AppendAfterInitNeedsAnOwnCatalog(t *testing.T) {
	original := append([]string(nil), GlobalRoleIDs...)
	t.Cleanup(func() { GlobalRoleIDs = original })

	GlobalRoleIDs = append(GlobalRoleIDs, "LATE_ROLE")
	if strings.Contains(DefaultGrantCatalog.Queries()[QCheckGlobalRole], "LATE_ROLE") {
		t.Error("DefaultGrantCatalog unexpectedly saw a post-init append")
	}
	if !strings.Contains(NewGrantCatalog().Queries()[QCheckGlobalRole], "LATE_ROLE") {
		t.Error("a catalog built after the append should carry the new role")
	}
}
