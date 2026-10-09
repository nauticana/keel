package data

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// grantRows answers the generated check and read queries from fixed grants,
// counting each query as the database would see it.
type grantRows struct {
	port.QueryService
	grants  []testGrant
	queries int
	fail    bool
	columns int // read-query width; 0 means 5
}

type testGrant struct {
	object, action, lowLimit string
	bypass                   bool
}

func (g *grantRows) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	g.queries++
	if g.fail {
		return nil, errors.New("connection refused")
	}
	res := &model.QueryResult{}
	switch name {
	case DefaultGrantCatalog.CheckQuery(model.PrincipalUser):
		object, action, scope := args[0], args[1], args[3]
		for _, gr := range g.grants {
			if gr.object == object && gr.action == action && (gr.lowLimit == scope || gr.lowLimit == "*") {
				res.Rows = append(res.Rows, []any{gr.lowLimit, nil, gr.bypass})
			}
		}
	case DefaultGrantCatalog.ReadQuery(model.PrincipalUser):
		for _, gr := range g.grants {
			row := []any{gr.object, gr.action, gr.lowLimit, nil, gr.bypass}
			if g.columns > 0 {
				row = row[:g.columns]
			}
			res.Rows = append(res.Rows, row)
		}
	default:
		return nil, errors.New("unexpected query " + name)
	}
	return res, nil
}

func TestActionGrantsMatchesCheckActionPermission(t *testing.T) {
	qs := &grantRows{grants: []testGrant{
		{object: "TABLE", action: "READ", lowLimit: "*"},
		{object: "TABLE", action: "UPDATE", lowLimit: "invoice"},
		{object: "REPORT", action: "RUN", lowLimit: "sales"},
		{object: "REPORT", action: "RUN", lowLimit: "*"},
		{object: "REPORT", action: "EXPORT", lowLimit: "sal*"},
		{object: "MCP", action: "CALL", lowLimit: "*"},
		{object: "AUDIT", action: "READ", lowLimit: "*", bypass: true},
	}}
	repo := &AbstractRepository{AuthQuery: qs}
	principal := model.UserPrincipal(7)
	grants, err := repo.ActionGrants(context.Background(), principal)
	if err != nil || qs.queries != 1 {
		t.Fatalf("ActionGrants = %v after %d queries", err, qs.queries)
	}
	for _, object := range []string{"TABLE", "REPORT", "MCP", "AUDIT", "OTHER", ""} {
		for _, action := range []string{"READ", "UPDATE", "RUN", "EXPORT", "CALL", ""} {
			for _, scope := range []string{"invoice", "sales", "salary", "*", ""} {
				wantOK, wantOwn := repo.CheckActionPermission(context.Background(), principal, object, action, scope)
				gotOK, gotOwn := grants.Allows(object, action, scope)
				if gotOK != wantOK || gotOwn != wantOwn {
					t.Errorf("%s/%s/%q: set = (%v,%v), check = (%v,%v)", object, action, scope, gotOK, gotOwn, wantOK, wantOwn)
				}
			}
		}
	}
	if ok, own := grants.Allows("REPORT", "RUN", "sales"); !ok || own {
		t.Error("an exact grant must win over '*'")
	}
	if ok, _ := grants.Allows("REPORT", "EXPORT", "salary"); ok {
		t.Error("only exact and '*' low_limit values may match")
	}
	if ok, own := grants.Allows("AUDIT", "READ", "event"); !ok || own {
		t.Error("bypass_scope must suppress row scoping")
	}
}

func TestActionGrantsFailsClosed(t *testing.T) {
	ctx := context.Background()
	if _, err := (&AbstractRepository{}).ActionGrants(ctx, model.UserPrincipal(7)); err == nil {
		t.Error("an unwired repository must error")
	}
	repo := &AbstractRepository{AuthQuery: &grantRows{grants: []testGrant{{object: "TABLE", action: "READ", lowLimit: "*"}}}}
	if _, err := repo.ActionGrants(ctx, model.Principal{}); err == nil {
		t.Error("a zero principal must error")
	}
	if _, err := repo.ActionGrants(ctx, model.Principal{Kind: "agent", ID: "a"}); err == nil {
		t.Error("an unregistered kind must error")
	}
	short := &AbstractRepository{AuthQuery: &grantRows{grants: []testGrant{{object: "TABLE", action: "READ", lowLimit: "*"}}, columns: 4}}
	if _, err := short.ActionGrants(ctx, model.UserPrincipal(7)); err == nil {
		t.Error("a read query without bypass_scope must error, not panic")
	}
	failing := &AbstractRepository{AuthQuery: &grantRows{fail: true}}
	if _, err := failing.ActionGrants(ctx, model.UserPrincipal(7)); err == nil {
		t.Error("a query failure must surface")
	}
	var zero model.GrantSet
	if ok, _ := zero.Allows("TABLE", "READ", "*"); ok {
		t.Error("the zero GrantSet must allow nothing")
	}
}
