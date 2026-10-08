package sso

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/model"
)

func newProvisioning(t *testing.T) (*Provisioning, *fixture) {
	t.Helper()
	f := newFixture(t)
	f.store.scim = newSCIMStore()
	return &Provisioning{DB: &storeDB{s: f.store}, Users: f.users, Domains: &domain.Service{DB: &storeDB{s: f.store}}}, f
}

func scimUser(userName, email string, active bool) *SCIMUser {
	b := SCIMBool(active)
	return &SCIMUser{UserName: userName, ExternalID: "ext-" + userName, Name: &SCIMName{GivenName: "Ada"},
		Emails: []SCIMEmail{{Value: email, Primary: true}}, Active: &b}
}

func TestProvisioningTokens(t *testing.T) {
	p, _ := newProvisioning(t)
	ctx := context.Background()
	id, token, err := p.IssueToken(ctx, acme, 5, "Entra", 365)
	if err != nil || id == 0 || len(token) < 40 {
		t.Fatalf("IssueToken = %d %q %v", id, token, err)
	}
	if partner, err := p.Authenticate(ctx, token); err != nil || partner != acme {
		t.Fatalf("Authenticate = %d %v", partner, err)
	}
	for _, bad := range []string{"", "scim_unknown", token + "x", "Bearer " + token} {
		if _, err := p.Authenticate(ctx, bad); !errors.Is(err, ErrSCIMUnauthorized) {
			t.Errorf("Authenticate(%q) = %v", bad, err)
		}
	}
	if err := p.RevokeToken(ctx, 99, id); !errors.Is(err, ErrSCIMNotFound) {
		t.Fatalf("revoke by another partner = %v", err)
	}
	if err := p.RevokeToken(ctx, acme, id); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Authenticate(ctx, token); !errors.Is(err, ErrSCIMUnauthorized) {
		t.Fatalf("revoked token = %v", err)
	}
	for i := 0; i < config.Config().SCIMMaxActiveTokens; i++ {
		if _, _, err := p.IssueToken(ctx, acme, 5, "t", 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := p.IssueToken(ctx, acme, 5, "t", 0); !errors.Is(err, ErrSCIMTooMany) {
		t.Fatalf("sixth token = %v", err)
	}
	for _, days := range []int{-1, config.Config().SCIMTokenMaxDays + 1} {
		if _, _, err := p.IssueToken(ctx, 77, 5, "t", days); !errors.Is(err, ErrSCIMInvalidValue) {
			t.Errorf("%d days = %v", days, err)
		}
	}
}

func TestProvisionUserLifecycle(t *testing.T) {
	p, f := newProvisioning(t)
	ctx := context.Background()
	u, err := p.CreateUser(ctx, acme, scimUser("Ada@Acme.example", "ada@acme.example", true))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	uid, _ := strconv.Atoi(u.ID)
	if u.UserName != "ada@acme.example" || f.users.accounts[uid].PartnerId != acme {
		t.Fatalf("created %+v account %+v", u, f.users.accounts[uid])
	}
	if _, err := p.CreateUser(ctx, acme, scimUser("ada@acme.example", "ada2@acme.example", true)); !errors.Is(err, ErrSCIMConflict) {
		t.Fatalf("duplicate userName = %v", err)
	}
	list, err := p.ListUsers(ctx, acme, `userName eq "ADA@acme.example"`, 1, 10)
	if err != nil || list.TotalResults != 1 || list.Resources[0].ID != u.ID {
		t.Fatalf("filter = %+v %v", list, err)
	}
	if list, err := p.ListUsers(ctx, 99, "", 1, 10); err != nil || list.TotalResults != 0 {
		t.Fatalf("another partner sees %+v %v", list, err)
	}
	if _, err := p.GetUser(ctx, 99, u.ID); !errors.Is(err, ErrSCIMNotFound) {
		t.Fatalf("another partner reads the user: %v", err)
	}

	// Entra deactivates with a string boolean and a capitalized op.
	ops := []SCIMPatchOp{{Op: "Replace", Path: "active", Value: json.RawMessage(`"False"`)}}
	if u, err = p.PatchUser(ctx, acme, u.ID, ops); err != nil || u.active() {
		t.Fatalf("deactivate = %+v %v", u, err)
	}
	if len(f.users.ended) != 1 || f.users.ended[0] != uid {
		t.Fatalf("deactivation must end the membership at once: %v", f.users.ended)
	}
	ops = []SCIMPatchOp{{Op: "replace", Value: json.RawMessage(`{"active":true,"name.familyName":"L"}`)}}
	if u, err = p.PatchUser(ctx, acme, u.ID, ops); err != nil || !u.active() || f.users.accounts[uid].PartnerId != acme {
		t.Fatalf("reactivate = %+v %v", u, err)
	}
	if err := p.DeleteUser(ctx, acme, u.ID); err != nil || len(f.users.ended) != 2 {
		t.Fatalf("delete = %v, ended %v", err, f.users.ended)
	}
	if _, err := p.GetUser(ctx, acme, u.ID); !errors.Is(err, ErrSCIMNotFound) {
		t.Fatalf("deleted user = %v", err)
	}
}

func TestProvisionUserRefusals(t *testing.T) {
	p, f := newProvisioning(t)
	ctx := context.Background()
	f.users.accounts[8] = &model.UserSession{Id: 8, Email: "eve@acme.example", PartnerId: 99}
	for name, in := range map[string]*SCIMUser{
		"email outside held domains": scimUser("ada@gmail.com", "ada@gmail.com", true),
		"email of another tenant":    scimUser("x@other.example", "x@other.example", true),
		"no userName":                scimUser("", "ada@acme.example", true),
		"no email":                   {UserName: "ada"},
	} {
		if _, err := p.CreateUser(ctx, acme, in); !errors.Is(err, ErrSCIMInvalidValue) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := p.CreateUser(ctx, acme, scimUser("eve@acme.example", "eve@acme.example", true)); !errors.Is(err, ErrSCIMConflict) {
		t.Fatalf("account of another partner = %v", err)
	}
	f.users.accounts[9] = &model.UserSession{Id: 9, Email: "bob@acme.example"}
	if u, err := p.CreateUser(ctx, acme, scimUser("bob@acme.example", "bob@acme.example", true)); err != nil || u.ID != "9" || f.users.accounts[9].PartnerId != acme {
		t.Fatalf("adopting a partnerless account = %+v %v", u, err)
	}
	if _, err := p.ListUsers(ctx, acme, `title sw "x"`, 1, 10); !errors.Is(err, ErrSCIMInvalidFilter) {
		t.Fatalf("unsupported filter = %v", err)
	}
}

func TestProvisioningDeactivationCanBeRetried(t *testing.T) {
	p, f := newProvisioning(t)
	ctx := context.Background()
	f.users.accounts[9] = &model.UserSession{Id: 9, Email: "ada@acme.example", PartnerId: acme}
	f.users.endErr = errors.New("revocation unavailable")
	inactive := scimUser("ada@acme.example", "ada@acme.example", false)
	if _, err := p.CreateUser(ctx, acme, inactive); !errors.Is(err, f.users.endErr) {
		t.Fatalf("inactive create = %v", err)
	}
	if _, err := p.GetUser(ctx, acme, "9"); !errors.Is(err, ErrSCIMNotFound) {
		t.Fatalf("failed create left an unretryable resource: %v", err)
	}
	f.users.endErr = nil
	u, err := p.CreateUser(ctx, acme, inactive)
	if err != nil {
		t.Fatalf("create retry: %v", err)
	}

	active := SCIMBool(true)
	u.Active = &active
	if u, err = p.ReplaceUser(ctx, acme, u.ID, u); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	f.users.endErr = errors.New("revocation unavailable")
	if _, err := p.PatchUser(ctx, acme, u.ID, []SCIMPatchOp{{Op: "replace", Path: "active", Value: json.RawMessage(`false`)}}); !errors.Is(err, f.users.endErr) {
		t.Fatalf("deactivate = %v", err)
	}
	f.users.endErr = nil
	if _, err := p.PatchUser(ctx, acme, u.ID, []SCIMPatchOp{{Op: "replace", Path: "active", Value: json.RawMessage(`false`)}}); err != nil {
		t.Fatalf("deactivate retry: %v", err)
	}

	active = true
	u.Active = &active
	if u, err = p.ReplaceUser(ctx, acme, u.ID, u); err != nil {
		t.Fatalf("second reactivate: %v", err)
	}
	f.users.endErr = errors.New("revocation unavailable")
	if err := p.DeleteUser(ctx, acme, u.ID); !errors.Is(err, f.users.endErr) {
		t.Fatalf("delete = %v", err)
	}
	if _, err := p.GetUser(ctx, acme, u.ID); err != nil {
		t.Fatalf("failed delete removed the resource: %v", err)
	}
	f.users.endErr = nil
	if err := p.DeleteUser(ctx, acme, u.ID); err != nil {
		t.Fatalf("delete retry: %v", err)
	}
}

func TestGroupsMapRolesThroughTheActiveConnection(t *testing.T) {
	p, f := newProvisioning(t)
	ctx := context.Background()
	f.store.mappings = [][3]string{{"groups", "Admins", "PARTNER_ADMIN"}, {"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", "obj-1", "BILLING"}}
	u, err := p.CreateUser(ctx, acme, scimUser("ada@acme.example", "ada@acme.example", true))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(u.ID)
	g, err := p.CreateGroup(ctx, acme, &SCIMGroup{DisplayName: "Admins", ExternalID: "obj-1", Members: []SCIMRef{{Value: u.ID}}})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if len(f.store.grants[uid]) != 2 {
		t.Fatalf("grants by name and external id = %v", f.store.grants[uid])
	}
	// Entra removes a member through a filtered path.
	ops := []SCIMPatchOp{{Op: "Remove", Path: `members[value eq "` + u.ID + `"]`}}
	if _, err := p.PatchGroup(ctx, acme, g.ID, ops); err != nil {
		t.Fatal(err)
	}
	if len(f.store.grants[uid]) != 0 {
		t.Fatalf("removal kept grants %v", f.store.grants[uid])
	}
	ops = []SCIMPatchOp{{Op: "Add", Path: "members", Value: json.RawMessage(`[{"value":"` + u.ID + `"}]`)}, {Op: "Replace", Path: "displayName", Value: json.RawMessage(`"Staff"`)}}
	if g, err = p.PatchGroup(ctx, acme, g.ID, ops); err != nil || g.DisplayName != "Staff" || len(g.Members) != 1 {
		t.Fatalf("patch = %+v %v", g, err)
	}
	if _, ok := f.store.grants[uid]["BILLING"]; !ok || len(f.store.grants[uid]) != 1 {
		t.Fatalf("after rename only the external id maps: %v", f.store.grants[uid])
	}
	if err := p.DeleteGroup(ctx, acme, g.ID); err != nil || len(f.store.grants[uid]) != 0 {
		t.Fatalf("delete group = %v, grants %v", err, f.store.grants[uid])
	}
	if _, err := p.CreateGroup(ctx, acme, &SCIMGroup{DisplayName: "X", Members: []SCIMRef{{Value: "12345"}}}); !errors.Is(err, ErrSCIMInvalidValue) {
		t.Fatalf("unknown member = %v", err)
	}
	if _, err := p.GetGroup(ctx, 99, g.ID, true); !errors.Is(err, ErrSCIMNotFound) {
		t.Fatalf("another partner = %v", err)
	}
}

func TestGroupMemberLimitAppliesToPersistedMembership(t *testing.T) {
	p, _ := newProvisioning(t)
	saved := config.Config().SCIMMaxGroupMembers
	config.Config().SCIMMaxGroupMembers = 1
	t.Cleanup(func() { config.Config().SCIMMaxGroupMembers = saved })

	u1, err := p.CreateUser(context.Background(), acme, scimUser("a@acme.example", "a@acme.example", true))
	if err != nil {
		t.Fatal(err)
	}
	u2, err := p.CreateUser(context.Background(), acme, scimUser("b@acme.example", "b@acme.example", true))
	if err != nil {
		t.Fatal(err)
	}
	g, err := p.CreateGroup(context.Background(), acme, &SCIMGroup{DisplayName: "Bounded", Members: []SCIMRef{{Value: u1.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.PatchGroup(context.Background(), acme, g.ID, []SCIMPatchOp{{Op: "add", Path: "members", Value: json.RawMessage(`[{"value":"` + u2.ID + `"}]`)}})
	if !errors.Is(err, ErrSCIMTooMany) {
		t.Fatalf("adding a second member with limit one = %v", err)
	}
}

func TestProvisionUserRejectsOversizedNames(t *testing.T) {
	p, _ := newProvisioning(t)
	in := scimUser("ada@acme.example", "ada@acme.example", true)
	in.Name.GivenName = strings.Repeat("x", 81)
	if _, err := p.CreateUser(context.Background(), acme, in); !errors.Is(err, ErrSCIMInvalidValue) {
		t.Fatalf("oversized givenName = %v", err)
	}
}

func TestProvisionedUserSignInKeepsDirectoryRoles(t *testing.T) {
	p, f := newProvisioning(t)
	ctx := context.Background()
	f.store.mappings = [][3]string{{"groups", "Admins", "PARTNER_ADMIN"}}
	u, _ := p.CreateUser(ctx, acme, scimUser("ada@acme.example", "ada@acme.example", true))
	uid, _ := strconv.Atoi(u.ID)
	if _, err := p.CreateGroup(ctx, acme, &SCIMGroup{DisplayName: "Admins", Members: []SCIMRef{{Value: u.ID}}}); err != nil {
		t.Fatal(err)
	}
	f.users.links[issuer+"|sub-1"] = uid
	f.provider.assertion.Claims = map[string][]string{}
	if _, err := f.signIn(t, "ada@acme.example"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.store.grants[uid]["PARTNER_ADMIN"]; !ok {
		t.Fatal("a token without the group claim must not end directory roles")
	}
}

func TestPatchParsing(t *testing.T) {
	u := &SCIMUser{UserName: "a"}
	ops := []SCIMPatchOp{
		{Op: "add", Path: `emails[type eq "work"].value`, Value: json.RawMessage(`"a@acme.example"`)},
		{Op: "replace", Path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", Value: json.RawMessage(`"x"`)},
		{Op: "remove", Path: "externalId"},
	}
	if err := applyUserPatch(u, ops); err != nil || u.email() != "a@acme.example" {
		t.Fatalf("patch = %+v %v", u, err)
	}
	for name, bad := range map[string][]SCIMPatchOp{
		"unknown op":      {{Op: "move", Path: "active"}},
		"remove active":   {{Op: "remove", Path: "active"}},
		"bad boolean":     {{Op: "replace", Path: "active", Value: json.RawMessage(`"maybe"`)}},
		"pathless remove": {{Op: "remove"}},
	} {
		if err := applyUserPatch(&SCIMUser{UserName: "a"}, bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := parseGroupPatch([]SCIMPatchOp{{Op: "replace", Path: "owner", Value: json.RawMessage(`"x"`)}}); !errors.Is(err, ErrSCIMInvalidPath) {
		t.Fatalf("unsupported group path = %v", err)
	}
	if _, err := ParseSCIMFilter(`userName eq "a" and active eq true`, "userName"); !errors.Is(err, ErrSCIMInvalidFilter) {
		t.Fatalf("compound filter = %v", err)
	}
}

func TestActivationMapsProvisionedGroups(t *testing.T) {
	p, f := newProvisioning(t)
	ctx := context.Background()
	f.store.connections[connID].Status = StatusDraft
	u, _ := p.CreateUser(ctx, acme, scimUser("ada@acme.example", "ada@acme.example", true))
	uid, _ := strconv.Atoi(u.ID)
	if _, err := p.CreateGroup(ctx, acme, &SCIMGroup{DisplayName: "Admins", Members: []SCIMRef{{Value: u.ID}}}); err != nil {
		t.Fatal(err)
	}
	if len(f.store.grants[uid]) != 0 {
		t.Fatal("no roles before a connection is active")
	}
	f.store.mappings = [][3]string{{"groups", "Admins", "PARTNER_ADMIN"}}
	if err := f.svc.Activate(ctx, acme, 5, connID); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.store.grants[uid]["PARTNER_ADMIN"]; !ok {
		t.Fatalf("activation must map provisioned groups: %v", f.store.grants[uid])
	}
}
