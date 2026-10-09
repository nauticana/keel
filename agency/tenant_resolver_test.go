package agency

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/clock"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type tenantDB struct {
	port.DatabaseRepository
	port.QueryService
	activeUsers map[int64]bool
	own         map[int64][][]any
	partners    map[int64]string
	agencyUsers map[int64]bool
	queries     int
	fail        bool
}

func (d *tenantDB) GetQueryService(context.Context, map[string]string) port.QueryService { return d }

func (d *tenantDB) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	d.queries++
	if d.fail {
		return nil, errors.New("connection refused")
	}
	id := args[0].(int64)
	res := &model.QueryResult{}
	switch name {
	case qTenantUserActive:
		if d.activeUsers[id] {
			res.Rows = [][]any{{1}}
		}
	case qTenantOwn:
		res.Rows = d.own[id]
	case qTenantPartner:
		if caption, ok := d.partners[id]; ok {
			res.Rows = [][]any{{id, caption}}
		}
	default:
		return nil, errors.New("unexpected query " + name)
	}
	return res, nil
}

func (d *tenantDB) CheckActionPermission(_ context.Context, p model.Principal, object, action, scope string) (bool, bool) {
	return object == "AGENCY" && action == "MANAGE_CLIENTS" && scope == "agency_clients" && d.agencyUsers[int64(p.ID.(int))], false
}

type tenantDelegations map[int64][]model.AgencyDelegation

func (d tenantDelegations) ActiveFor(_ context.Context, agencyPartnerID int64) ([]model.AgencyDelegation, error) {
	return d[agencyPartnerID], nil
}

func (d tenantDelegations) HasRole(context.Context, int64, int64, string) error { return nil }

func roles(codes ...string) []model.AgencyRoleGrant {
	out := make([]model.AgencyRoleGrant, len(codes))
	for i, code := range codes {
		out[i] = model.AgencyRoleGrant{Role: code}
	}
	return out
}

func newTenantFixture() (*tenantDB, *TenantResolver) {
	db := &tenantDB{
		activeUsers: map[int64]bool{7: true, 8: true},
		own:         map[int64][][]any{7: {{int64(10), "Agency"}, {int64(11), "Own shop"}}, 8: {{int64(20), "Solo"}}},
		partners:    map[int64]string{30: "Keyed"},
		agencyUsers: map[int64]bool{7: true},
	}
	return db, &TenantResolver{
		DB: db,
		Delegations: tenantDelegations{10: {
			{ID: 100, ClientPartnerID: 40, ClientName: "Client A", Roles: roles("view", "publish")},
			{ID: 101, ClientPartnerID: 11, ClientName: "Own shop", Roles: roles("operate")},
			{ID: 102, ClientPartnerID: 41, ClientName: "Client B", Roles: roles("custom")},
			{ID: 103, ClientPartnerID: 42, ClientName: "Client C", Roles: roles("view")},
		}},
		Levels:         []string{"view", "operate", "publish"},
		LevelRoles:     map[string]string{"view": "PARTNER_OPER", "operate": "PARTNER_ADMIN", "publish": "PARTNER_ADMIN"},
		NeverDelegated: []string{"api_key", "partner_credential"},
	}
}

func TestTenantResolverListsOwnThenDelegated(t *testing.T) {
	_, r := newTenantFixture()
	tenants, err := r.Authorized(context.Background(), model.TenantCaller{UserID: 7})
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Tenant{
		{PartnerID: 10, Name: "Agency", Relationship: model.TenantOwn},
		{PartnerID: 11, Name: "Own shop", Relationship: model.TenantOwn},
		{PartnerID: 40, Name: "Client A", Relationship: model.TenantDelegated, Level: "publish", DelegationID: 100, AgencyPartnerID: 10},
		{PartnerID: 42, Name: "Client C", Relationship: model.TenantDelegated, Level: "view", DelegationID: 103, AgencyPartnerID: 10},
	}
	if len(tenants) != len(want) {
		t.Fatalf("tenants = %+v", tenants)
	}
	for i := range want {
		if tenants[i] != want[i] {
			t.Errorf("tenant %d = %+v, want %+v", i, tenants[i], want[i])
		}
	}
}

func TestTenantResolverKeepsHighestDelegationForSharedClient(t *testing.T) {
	db, r := newTenantFixture()
	db.own[7] = append(db.own[7], []any{int64(12), "Second agency"})
	r.Delegations = tenantDelegations{
		10: {{ID: 100, ClientPartnerID: 40, ClientName: "Client A", Roles: roles("view")}},
		12: {{ID: 104, ClientPartnerID: 40, ClientName: "Client A", Roles: roles("publish")}},
	}
	tenants, err := r.Authorized(context.Background(), model.TenantCaller{UserID: 7})
	if err != nil {
		t.Fatal(err)
	}
	if got := tenants[len(tenants)-1]; got.Level != "publish" || got.DelegationID != 104 || got.AgencyPartnerID != 12 {
		t.Fatalf("shared client tenant = %+v", got)
	}
}

func TestTenantResolverDelegationNeedsAgencyGrant(t *testing.T) {
	db, r := newTenantFixture()
	db.agencyUsers[7] = false
	tenants, err := r.Authorized(context.Background(), model.TenantCaller{UserID: 7})
	if err != nil || len(tenants) != 2 {
		t.Fatalf("without AGENCY/MANAGE_CLIENTS only own tenants: %+v, %v", tenants, err)
	}
	r.Delegations = nil
	db.agencyUsers[7] = true
	if tenants, _ := r.AuthorizedFresh(context.Background(), model.TenantCaller{UserID: 7}); len(tenants) != 2 {
		t.Fatalf("without a delegation resolver only own tenants: %+v", tenants)
	}
}

func TestTenantResolverCallers(t *testing.T) {
	_, r := newTenantFixture()
	ctx := context.Background()
	tenants, err := r.Authorized(ctx, model.TenantCaller{APIKeyPartnerID: 30})
	if err != nil || len(tenants) != 1 || tenants[0] != (model.Tenant{PartnerID: 30, Name: "Keyed", Relationship: model.TenantAPIKey}) {
		t.Fatalf("API key tenant = %+v, %v", tenants, err)
	}
	for name, caller := range map[string]model.TenantCaller{
		"zero":             {},
		"both":             {UserID: 7, APIKeyPartnerID: 30},
		"negative":         {UserID: -1, APIKeyPartnerID: 30},
		"inactive user":    {UserID: 9},
		"unknown key part": {APIKeyPartnerID: 31},
	} {
		if _, err := r.Authorized(ctx, caller); !errors.Is(err, ErrTenantCaller) {
			t.Errorf("%s: err = %v, want ErrTenantCaller", name, err)
		}
	}
}

func TestTenantResolverResolve(t *testing.T) {
	_, r := newTenantFixture()
	ctx := context.Background()
	user7 := model.TenantCaller{UserID: 7}
	if tenant, err := r.Resolve(ctx, user7, 40); err != nil || tenant.Level != "publish" {
		t.Errorf("Resolve(40) = %+v, %v", tenant, err)
	}
	for _, foreign := range []int64{41, 99, -1} {
		if _, err := r.Resolve(ctx, user7, foreign); !errors.Is(err, ErrTenantNotFound) {
			t.Errorf("Resolve(%d) err = %v, want ErrTenantNotFound", foreign, err)
		}
	}
	var choice *TenantChoiceError
	if _, err := r.Resolve(ctx, user7, 0); !errors.Is(err, ErrTenantRequired) || !errors.As(err, &choice) || len(choice.Choices) != 4 {
		t.Errorf("Resolve(0) with several = %v", err)
	}
	if tenant, err := r.Resolve(ctx, model.TenantCaller{UserID: 8}, 0); err != nil || tenant.PartnerID != 20 {
		t.Errorf("Resolve(0) with one = %+v, %v", tenant, err)
	}
}

func TestTenantResolverCacheExpiresAndFreshBypasses(t *testing.T) {
	db, r := newTenantFixture()
	fake := clock.NewFake(time.Unix(1_700_000_000, 0))
	r.Clock, r.CacheTTL = fake, time.Minute
	ctx := context.Background()
	caller := model.TenantCaller{UserID: 8}
	if _, err := r.Authorized(ctx, caller); err != nil {
		t.Fatal(err)
	}
	db.own[8] = nil
	if tenants, _ := r.Authorized(ctx, caller); len(tenants) != 1 {
		t.Fatalf("cached read = %+v", tenants)
	}
	fake.Advance(time.Minute)
	if tenants, _ := r.Authorized(ctx, caller); len(tenants) != 0 {
		t.Fatalf("expired cache served %+v", tenants)
	}

	db.own[8] = [][]any{{int64(20), "Solo"}}
	if tenants, _ := r.AuthorizedFresh(ctx, caller); len(tenants) != 1 {
		t.Fatalf("fresh read missed a new membership: %+v", tenants)
	}
	db.fail = true
	if _, err := r.AuthorizedFresh(ctx, caller); err == nil {
		t.Fatal("a query failure must surface")
	}
}

func TestTenantResolverPrincipalAndScopes(t *testing.T) {
	_, r := newTenantFixture()
	if p, ok := r.DelegationPrincipal("view"); !ok || p.Kind != model.PrincipalRole || p.ID != "PARTNER_OPER" {
		t.Errorf("view principal = %+v, %v", p, ok)
	}
	if _, ok := r.DelegationPrincipal("custom"); ok {
		t.Error("an unmapped level must not get a principal")
	}
	if r.Delegable("api_key") || !r.Delegable("partner_domain") {
		t.Error("NeverDelegated must withhold exactly its scopes")
	}
}
