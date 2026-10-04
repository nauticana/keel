package agency

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// roleStore stands in for one client's delegation, its role rows, and events.
// Rollback restores the snapshot taken at BeginTx.
type roleStore struct {
	now        time.Time
	catalogue  []string
	active     bool
	roles      map[string]*time.Time
	events     [][]any
	resolved   [][]any
	failExpire bool
	committed  bool
	rolledBack bool
	nextID     int64
	snapshot   func()
}

const (
	testDelegation = int64(77)
	testClient     = int64(5)
	testAgency     = int64(8)
	testActor      = int64(9)
)

func newRoleStore() *roleStore {
	return &roleStore{
		now:       time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC),
		catalogue: []string{"view", "operate", "publish"},
		active:    true,
		roles:     map[string]*time.Time{},
		nextID:    100,
	}
}

func (f *roleStore) begin() {
	active, events := f.active, append([][]any(nil), f.events...)
	roles := make(map[string]*time.Time, len(f.roles))
	for k, v := range f.roles {
		roles[k] = v
	}
	f.snapshot = func() { f.active, f.events, f.roles = active, events, roles }
}

func (f *roleStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	out := &model.QueryResult{}
	switch name {
	case qKnownDelegationRoles:
		for _, code := range f.catalogue {
			out.Rows = append(out.Rows, []any{code})
		}
	case qExpiryInFuture:
		out.Rows = [][]any{{args[0].(time.Time).After(f.now)}}
	case qDelegationLock, qDelegationForRevoke:
		if f.active && args[0] == testClient {
			out.Rows = [][]any{{testDelegation, testAgency}}
		}
	case qDelegationRoles:
		for _, role := range sortedRoles(f.roles) {
			out.Rows = append(out.Rows, []any{role, timeArg(f.roles[role])})
		}
	case qInsertDelegationRole:
		f.roles[args[1].(string)] = argTime(args[2])
	case qUpdateRoleExpiry:
		f.roles[args[2].(string)] = argTime(args[0])
	case qDeleteDelegationRole:
		delete(f.roles, args[1].(string))
	case qExpireDelegationRoles:
		if f.failExpire {
			return nil, errors.New("role update failed")
		}
		for _, role := range sortedRoles(f.roles) {
			old := f.roles[role]
			if old == nil || old.After(f.now) {
				now := f.now
				f.roles[role] = &now
				out.Rows = append(out.Rows, []any{role, timeArg(old), now})
			}
		}
	case qRevokeDelegation:
		if f.active {
			f.active = false
			out.Rows = [][]any{{testDelegation}}
		}
	case qInsertDelegationEvent:
		f.events = append(f.events, args)
	case qClientDelegation:
		if f.active {
			out.Rows = [][]any{{testDelegation, testClient, "Client", testAgency, "Agency", "R", f.now}}
		}
	case qListClients:
		out.Rows = [][]any{
			{int64(1), "Client", "", "", "V", testClient, testActor, f.now, f.now, "R"},
			{int64(2), "Prospect", "", "", "S", int64(0), int64(0), nil, nil, ""},
		}
	case qAgencyClientRoles:
		for _, role := range sortedRoles(f.roles) {
			out.Rows = append(out.Rows, []any{testClient, role, timeArg(f.roles[role])})
		}
	case qActiveDelegationsFor:
		out.Rows = f.resolved
	case qHasDelegationRole:
		for _, row := range f.resolved {
			if row[1] == args[1] && row[7] == args[2] {
				out.Rows = [][]any{{1}}
			}
		}
	}
	return out, nil
}

func argTime(v any) *time.Time {
	if v == nil {
		return nil
	}
	t := v.(time.Time)
	return &t
}

func (f *roleStore) GenID() int64                 { f.nextID++; return f.nextID }
func (f *roleStore) Commit(context.Context) error { f.committed = true; return nil }
func (f *roleStore) Rollback(context.Context) error {
	f.rolledBack = true
	f.snapshot()
	return nil
}

type roleRepo struct {
	port.DatabaseRepository
	store *roleStore
}

func (r roleRepo) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r.store
}

func (r roleRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	r.store.begin()
	return r.store, nil
}

func newRoleService(store *roleStore) *BaseAgencyService {
	return NewBaseAgencyService(roleRepo{store: store}, BaseAgencyServiceOptions{
		Now: func() time.Time { return store.now },
	})
}

func at(t time.Time) *time.Time { return &t }

func eventSummary(events [][]any) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, fmt.Sprintf("%v:%v:%v", e[3], e[4], e[2]))
	}
	return out
}

func TestSetDelegationRolesDiffsAndRecordsEachChange(t *testing.T) {
	store := newRoleStore()
	svc := newRoleService(store)
	ctx := context.Background()
	day := store.now.Add(24 * time.Hour)
	week := store.now.Add(7 * 24 * time.Hour)

	err := svc.SetDelegationRoles(ctx, testClient, testClient, []model.AgencyRoleGrant{
		{Role: " view "}, {Role: "operate", ExpiresAt: &day},
	}, testActor)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if got := eventSummary(store.events); strings.Join(got, ",") != "operate:G:9,view:G:9" {
		t.Fatalf("grant events = %v", got)
	}
	if store.roles["view"] != nil || store.roles["operate"] == nil || !store.roles["operate"].Equal(day) {
		t.Fatalf("roles after grant = %v", store.roles)
	}

	store.events, store.committed = nil, false
	err = svc.SetDelegationRoles(ctx, testClient, testClient, []model.AgencyRoleGrant{
		{Role: "operate", ExpiresAt: &week}, {Role: "publish"},
	}, testActor)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got := eventSummary(store.events); strings.Join(got, ",") != "view:R:9,operate:E:9,publish:G:9" {
		t.Fatalf("replace events = %v", got)
	}
	changed := store.events[1]
	if !changed[5].(time.Time).Equal(day) || !changed[6].(time.Time).Equal(week) {
		t.Fatalf("expiry event old/new = %v/%v", changed[5], changed[6])
	}
	if _, kept := store.roles["view"]; kept || len(store.roles) != 2 {
		t.Fatalf("roles after replace = %v", store.roles)
	}

	store.events, store.committed = nil, false
	nanos := week.Add(300 * time.Nanosecond)
	err = svc.SetDelegationRoles(ctx, testClient, testClient, []model.AgencyRoleGrant{
		{Role: "publish"}, {Role: "operate", ExpiresAt: &nanos},
	}, testActor)
	if err != nil || len(store.events) != 0 || !store.committed {
		t.Fatalf("no-op: err=%v events=%v committed=%v", err, store.events, store.committed)
	}

	err = svc.SetDelegationRoles(ctx, testClient, testClient, nil, testActor)
	if err != nil {
		t.Fatalf("remove all: %v", err)
	}
	if len(store.roles) != 0 || !store.active {
		t.Fatalf("remove all must clear roles without revoking: roles=%v active=%v", store.roles, store.active)
	}
	if got := eventSummary(store.events); strings.Join(got, ",") != "operate:R:9,publish:R:9" {
		t.Fatalf("remove events = %v", got)
	}
}

func TestSetDelegationRolesRejections(t *testing.T) {
	past := time.Date(2026, 10, 3, 11, 0, 0, 0, time.UTC)
	tooMany := make([]model.AgencyRoleGrant, maxDelegationRoles+1)
	for i := range tooMany {
		tooMany[i] = model.AgencyRoleGrant{Role: fmt.Sprintf("R%d", i)}
	}
	cases := []struct {
		name   string
		absent bool
		client int64
		caller int64
		user   int64
		grants []model.AgencyRoleGrant
		want   error
	}{
		{name: "agency caller", client: testClient, caller: testAgency, user: testActor,
			grants: []model.AgencyRoleGrant{{Role: "view"}}, want: port.ErrNotClientOwner},
		{name: "missing partner", user: testActor, want: port.ErrNotClientOwner},
		{name: "missing actor", client: testClient, caller: testClient, want: port.ErrNotClientOwner},
		{name: "blank role", client: testClient, caller: testClient, user: testActor,
			grants: []model.AgencyRoleGrant{{Role: "  "}}, want: port.ErrInvalidDelegationRole},
		{name: "unknown role", client: testClient, caller: testClient, user: testActor,
			grants: []model.AgencyRoleGrant{{Role: "view"}, {Role: "unknown"}}, want: port.ErrInvalidDelegationRole},
		{name: "duplicate role", client: testClient, caller: testClient, user: testActor,
			grants: []model.AgencyRoleGrant{{Role: "view"}, {Role: " view"}}, want: port.ErrDuplicateDelegationRole},
		{name: "too many", client: testClient, caller: testClient, user: testActor,
			grants: tooMany, want: port.ErrTooManyDelegationRoles},
		{name: "past expiry", client: testClient, caller: testClient, user: testActor,
			grants: []model.AgencyRoleGrant{{Role: "view"}, {Role: "operate", ExpiresAt: &past}}, want: port.ErrDelegationExpiryPast},
		{name: "revoked or absent", absent: true, client: testClient, caller: testClient, user: testActor,
			grants: []model.AgencyRoleGrant{{Role: "view"}}, want: port.ErrAgencyNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newRoleStore()
			store.active = !tc.absent
			err := newRoleService(store).SetDelegationRoles(context.Background(), tc.client, tc.caller, tc.grants, tc.user)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if store.committed || len(store.events) != 0 || len(store.roles) != 0 {
				t.Fatalf("rejected change committed=%v events=%d roles=%v", store.committed, len(store.events), store.roles)
			}
		})
	}
}

func TestRevokeExpiresOpenRolesAndKeepsRows(t *testing.T) {
	store := newRoleStore()
	future := store.now.Add(time.Hour)
	expired := store.now.Add(-time.Hour)
	store.roles = map[string]*time.Time{"view": nil, "operate": &future, "publish": &expired}

	if err := newRoleService(store).RevokeDelegation(context.Background(), testClient, testClient, testActor); err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	if store.active || !store.committed {
		t.Fatalf("delegation active=%v committed=%v", store.active, store.committed)
	}
	if len(store.roles) != 3 || !store.roles["view"].Equal(store.now) || !store.roles["operate"].Equal(store.now) ||
		!store.roles["publish"].Equal(expired) {
		t.Fatalf("roles after revoke = %v", store.roles)
	}
	if got := eventSummary(store.events); strings.Join(got, ",") != "operate:E:9,view:E:9" {
		t.Fatalf("revoke events = %v", got)
	}
	if e := store.events[0]; !e[5].(time.Time).Equal(future) || !e[6].(time.Time).Equal(store.now) {
		t.Fatalf("O expiry event old/new = %v/%v", e[5], e[6])
	}
	if e := store.events[1]; e[5] != nil {
		t.Fatalf("open-ended role old expiry = %v, want nil", e[5])
	}
}

func TestRevokeRollsBackWhenRoleExpiryFails(t *testing.T) {
	store := newRoleStore()
	store.roles = map[string]*time.Time{"view": nil}
	store.failExpire = true

	err := newRoleService(store).RevokeDelegation(context.Background(), testClient, testClient, testActor)
	if err == nil || !strings.Contains(err.Error(), "role update failed") {
		t.Fatalf("err = %v, want wrapped role update failure", err)
	}
	if store.committed || !store.rolledBack || !store.active || store.roles["view"] != nil || len(store.events) != 0 {
		t.Fatalf("revoke not rolled back: committed=%v rolledBack=%v active=%v roles=%v events=%d",
			store.committed, store.rolledBack, store.active, store.roles, len(store.events))
	}
}

func TestDelegationResolver(t *testing.T) {
	store := newRoleStore()
	svc := newRoleService(store)
	ctx := context.Background()
	if err := svc.HasRole(ctx, testAgency, testClient, "view"); !errors.Is(err, port.ErrDelegationNoAccess) {
		t.Fatalf("no delegation: err = %v", err)
	}

	later := store.now.Add(time.Hour)
	store.resolved = [][]any{
		{testDelegation, testClient, "Client", testAgency, "Agency", "R", store.now, "operate", later},
		{testDelegation, testClient, "Client", testAgency, "Agency", "R", store.now, "view", nil},
		{int64(78), int64(6), "Other", testAgency, "Agency", "W", store.now, "publish", nil},
	}
	active, err := svc.ActiveFor(ctx, testAgency)
	if err != nil {
		t.Fatalf("ActiveFor: %v", err)
	}
	if len(active) != 2 || len(active[0].Roles) != 2 || active[0].Roles[0].Role != "operate" ||
		!active[0].Roles[0].ExpiresAt.Equal(later) || active[0].Roles[1].ExpiresAt != nil ||
		len(active[1].Roles) != 1 || active[1].ClientPartnerID != 6 {
		t.Fatalf("ActiveFor = %+v", active)
	}
	if err = svc.HasRole(ctx, testAgency, testClient, " operate "); err != nil {
		t.Fatalf("HasRole operate: %v", err)
	}
	for _, role := range []string{"publish", "", " "} {
		if err = svc.HasRole(ctx, testAgency, testClient, role); !errors.Is(err, port.ErrDelegationNoAccess) {
			t.Fatalf("HasRole %q: err = %v, want ErrDelegationNoAccess", role, err)
		}
	}
	if err = svc.HasRole(ctx, 0, testClient, "operate"); !errors.Is(err, port.ErrDelegationNoAccess) {
		t.Fatalf("zero agency: err = %v", err)
	}
}

// Exclusions live in SQL: revoked delegations, expired roles, and inactive
// agencies must not resolve; revocation must never violate the grant check.
func TestDelegationRoleQueriesFailClosed(t *testing.T) {
	predicates := []string{
		"d.status = 'A'",
		"r.expires_at IS NULL OR r.expires_at > CURRENT_TIMESTAMP",
		"p.approved_at IS NOT NULL AND p.suspended = FALSE",
	}
	for _, name := range []string{qActiveDelegationsFor, qHasDelegationRole} {
		query := baseAgencyQueries[name]
		for _, predicate := range predicates {
			if !strings.Contains(query, predicate) {
				t.Errorf("%s lacks %q", name, predicate)
			}
		}
		if !strings.Contains(query, "agency_delegation_role r") {
			t.Errorf("%s must require a role row", name)
		}
	}
	if !strings.Contains(baseAgencyQueries[qExpireDelegationRoles], "GREATEST(LOCALTIMESTAMP, r.granted_at)") {
		t.Error("revocation expiry must not precede granted_at")
	}
}

func TestDelegationReadModelsCarryRoles(t *testing.T) {
	store := newRoleStore()
	later := store.now.Add(time.Hour)
	store.roles = map[string]*time.Time{"operate": &later, "view": nil}
	svc := newRoleService(store)

	delegation, err := svc.ClientDelegation(context.Background(), testClient)
	if err != nil {
		t.Fatalf("ClientDelegation: %v", err)
	}
	if len(delegation.Roles) != 2 || delegation.Roles[0].Role != "operate" || !delegation.Roles[0].ExpiresAt.Equal(later) {
		t.Fatalf("delegation roles = %+v", delegation.Roles)
	}
	clients, err := svc.ListClients(context.Background(), testAgency)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients[0].Roles) != 2 || clients[1].Roles != nil {
		t.Fatalf("client roles = %+v / %+v", clients[0].Roles, clients[1].Roles)
	}
}
