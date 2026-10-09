package sso

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/nauticana/keel/config"
)

func patchOp(op, path, value string) SCIMPatchOp {
	o := SCIMPatchOp{Op: op, Path: path}
	if value != "" {
		o.Value = json.RawMessage(value)
	}
	return o
}

func TestUserPatchPaths(t *testing.T) {
	for name, c := range map[string]struct {
		op   SCIMPatchOp
		want error
	}{
		"phone numbers":               {patchOp("add", `phoneNumbers[type eq "work"].value`, `"1"`), nil},
		"addresses":                   {patchOp("replace", `addresses[type eq "work"].streetAddress`, `"x"`), nil},
		"title":                       {patchOp("replace", "title", `"x"`), nil},
		"middle name":                 {patchOp("replace", "name.middleName", `"x"`), nil},
		"core urn":                    {patchOp("replace", SchemaUser+":name.givenName", `"x"`), nil},
		"enterprise attribute":        {patchOp("replace", SchemaEnterpriseUser+":department", `"x"`), nil},
		"enterprise manager":          {patchOp("replace", SchemaEnterpriseUser+":manager.value", `"x"`), nil},
		"enterprise object":           {patchOp("add", SchemaEnterpriseUser, `{"department":"x"}`), nil},
		"email primary":               {patchOp("replace", `emails[type eq "work"].primary`, `true`), nil},
		"undefined attribute":         {patchOp("replace", "favoriteColor", `"x"`), ErrSCIMInvalidPath},
		"undefined name part":         {patchOp("replace", "name.nickname", `"x"`), ErrSCIMInvalidPath},
		"undefined enterprise":        {patchOp("replace", SchemaEnterpriseUser+":shoeSize", `"x"`), ErrSCIMInvalidPath},
		"other extension":             {patchOp("replace", "urn:example:ext:1.0:User:x", `"x"`), ErrSCIMInvalidPath},
		"unsupported email filter":    {patchOp("replace", `emails[primary eq true].value`, `"x"`), ErrSCIMInvalidPath},
		"undefined email sub":         {patchOp("replace", `emails[type eq "work"].colour`, `"x"`), ErrSCIMInvalidPath},
		"pathless remove":             {patchOp("remove", "", ""), ErrSCIMNoTarget},
		"blank path remove":           {patchOp("remove", "  ", ""), ErrSCIMNoTarget},
		"pathless undefined":          {patchOp("replace", "", `{"favoriteColor":"x"}`), ErrSCIMInvalidPath},
		"pathless enterprise defined": {patchOp("replace", "", `{"`+SchemaEnterpriseUser+`:department":"x"}`), nil},
	} {
		u := &SCIMUser{UserName: "a", Emails: []SCIMEmail{{Value: "a@acme.example", Type: "work", Primary: true}}}
		if err := applyUserPatch(u, []SCIMPatchOp{c.op}); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s = %v, want %v", name, err, c.want)
		}
	}
}

func TestUserPatchEmailsByType(t *testing.T) {
	user := func() *SCIMUser {
		return &SCIMUser{UserName: "a", Emails: []SCIMEmail{
			{Value: "w@acme.example", Type: "work", Primary: true}, {Value: "h@acme.example", Type: "home"}}}
	}
	u := user()
	if err := applyUserPatch(u, []SCIMPatchOp{patchOp("remove", `emails[type eq "home"].value`, "")}); err != nil {
		t.Fatal(err)
	}
	if len(u.Emails) != 1 || u.email() != "w@acme.example" {
		t.Fatalf("removing the home email touched the others: %+v", u.Emails)
	}
	u = user()
	if err := applyUserPatch(u, []SCIMPatchOp{patchOp("remove", `emails[type eq "other"]`, "")}); err != nil || len(u.Emails) != 2 {
		t.Fatalf("removing an absent type = %+v %v", u.Emails, err)
	}
	u = user()
	if err := applyUserPatch(u, []SCIMPatchOp{patchOp("replace", `emails[type eq "WORK"].value`, `"n@acme.example"`)}); err != nil ||
		u.email() != "n@acme.example" || u.Emails[1].Value != "h@acme.example" {
		t.Fatalf("replace work = %+v %v", u.Emails, err)
	}
	u = user()
	qualified := SchemaUser + `:emails[type eq "work"].value`
	if err := applyUserPatch(u, []SCIMPatchOp{patchOp("replace", qualified, `"q@acme.example"`)}); err != nil || u.email() != "q@acme.example" {
		t.Fatalf("schema-qualified email = %+v %v", u.Emails, err)
	}
	u = user()
	if err := applyUserPatch(u, []SCIMPatchOp{patchOp("add", `emails[type eq "other"].value`, `"o@acme.example"`)}); err != nil ||
		len(u.Emails) != 3 || u.email() != "w@acme.example" {
		t.Fatalf("add other = %+v %v", u.Emails, err)
	}
	u = &SCIMUser{UserName: "a"}
	if err := applyUserPatch(u, []SCIMPatchOp{patchOp("add", `emails[type eq "work"].value`, `"a@acme.example"`)}); err != nil || u.email() != "a@acme.example" {
		t.Fatalf("first email = %+v %v", u.Emails, err)
	}
}

func TestPatchLimits(t *testing.T) {
	saved := config.Config().SCIMMaxPatchOperations
	config.Config().SCIMMaxPatchOperations = 1
	t.Cleanup(func() { config.Config().SCIMMaxPatchOperations = saved })
	ops := []SCIMPatchOp{patchOp("replace", "title", `"x"`), patchOp("replace", "title", `"y"`)}
	if err := applyUserPatch(&SCIMUser{}, ops); !errors.Is(err, ErrSCIMTooMany) {
		t.Errorf("user ops = %v", err)
	}
	if _, err := parseGroupPatch(ops); !errors.Is(err, ErrSCIMTooMany) {
		t.Errorf("group ops = %v", err)
	}
}

func TestGroupPatchPaths(t *testing.T) {
	for name, c := range map[string]struct {
		op   SCIMPatchOp
		want error
	}{
		"remove member by filter":  {patchOp("remove", `members[value eq "5"]`, ""), nil},
		"core urn display name":    {patchOp("replace", SchemaGroup+":displayName", `"x"`), nil},
		"pathless remove":          {patchOp("remove", "", ""), ErrSCIMNoTarget},
		"add on member filter":     {patchOp("add", `members[value eq "5"]`, `{"value":"6"}`), ErrSCIMMutability},
		"replace on member filter": {patchOp("replace", `members[value eq "5"]`, `{"value":"6"}`), ErrSCIMMutability},
		"member sub-attribute":     {patchOp("replace", `members[value eq "5"].display`, `"x"`), ErrSCIMInvalidPath},
		"undefined attribute":      {patchOp("replace", "owner", `"x"`), ErrSCIMInvalidPath},
	} {
		if _, err := parseGroupPatch([]SCIMPatchOp{c.op}); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s = %v, want %v", name, err, c.want)
		}
	}
	p, err := parseGroupPatch([]SCIMPatchOp{patchOp("remove", `members[value eq "Ab12"]`, "")})
	if err != nil || len(p.remove) != 1 || p.remove[0] != "Ab12" {
		t.Fatalf("member value must keep its case: %+v %v", p, err)
	}
}
