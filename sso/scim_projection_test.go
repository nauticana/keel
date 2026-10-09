package sso

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSCIMProjection(t *testing.T) {
	active := SCIMBool(true)
	user := &SCIMUser{
		Schemas: []string{SchemaUser}, ID: "7", ExternalID: "x", UserName: "ada", DisplayName: "Ada L", Active: &active,
		Name:   &SCIMName{GivenName: "Ada", FamilyName: "L"},
		Emails: []SCIMEmail{{Value: "a@acme.example", Type: "work", Primary: true}},
		Meta:   &SCIMMeta{ResourceType: "User", Location: "https://x/Users/7"},
	}
	for name, c := range map[string]struct {
		attributes, excluded string
		want                 string
	}{
		"none":            {"", "", `{"active":true,"displayName":"Ada L","emails":[{"primary":true,"type":"work","value":"a@acme.example"}],"externalId":"x","id":"7","meta":{"location":"https://x/Users/7","resourceType":"User"},"name":{"familyName":"L","givenName":"Ada"},"schemas":["` + SchemaUser + `"],"userName":"ada"}`},
		"attributes":      {"USERNAME, active", "", `{"active":true,"id":"7","schemas":["` + SchemaUser + `"],"userName":"ada"}`},
		"sub-attributes":  {"name.givenName,emails.value", "", `{"emails":[{"value":"a@acme.example"}],"id":"7","name":{"givenName":"Ada"},"schemas":["` + SchemaUser + `"]}`},
		"whole wins":      {"name.givenName,name", "", `{"id":"7","name":{"familyName":"L","givenName":"Ada"},"schemas":["` + SchemaUser + `"]}`},
		"urn qualified":   {SchemaUser + ":userName," + SchemaEnterpriseUser + ":department", "", `{"id":"7","schemas":["` + SchemaUser + `"],"userName":"ada"}`},
		"meta requested":  {"meta.location", "", `{"id":"7","meta":{"location":"https://x/Users/7"},"schemas":["` + SchemaUser + `"]}`},
		"always returned": {"", "id,schemas,meta,emails,name.familyName,active,displayName,externalId", `{"id":"7","name":{"givenName":"Ada"},"schemas":["` + SchemaUser + `"],"userName":"ada"}`},
		"emptied":         {"name.middleName", "", `{"id":"7","schemas":["` + SchemaUser + `"]}`},
		"both":            {"userName,name", "name", `{"id":"7","schemas":["` + SchemaUser + `"],"userName":"ada"}`},
	} {
		got, err := NewSCIMProjection(SchemaUser, c.attributes, c.excluded).Apply(user)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(got)
		var gotMap, wantMap map[string]any
		_ = json.Unmarshal(raw, &gotMap)
		_ = json.Unmarshal([]byte(c.want), &wantMap)
		if !reflect.DeepEqual(gotMap, wantMap) {
			t.Errorf("%s = %s", name, raw)
		}
	}
	if user.Name.FamilyName != "L" || len(user.Emails) != 1 {
		t.Fatal("projection must not change the resource")
	}
	for c, want := range map[[2]string]bool{
		{"", ""}:                       true,
		{"displayName", ""}:            false,
		{"members.value", ""}:          true,
		{"", "members"}:                false,
		{"", "Members.display"}:        true,
		{"displayname", "id"}:          false,
		{SchemaGroup + ":members", ""}: true,
	} {
		if got := NewSCIMProjection(SchemaGroup, c[0], c[1]).Includes("members"); got != want {
			t.Errorf("Includes(members) with %q = %v", c, got)
		}
	}
}

func TestSCIMSchemasDescribeKeptAttributes(t *testing.T) {
	schemas := SCIMSchemas()
	attrs := map[string]SCIMAttribute{}
	for _, s := range schemas {
		if len(s.Schemas) != 1 || s.Schemas[0] != SchemaSchema || s.Meta == nil || s.Meta.ResourceType != "Schema" {
			t.Errorf("%s: schemas %v meta %+v", s.ID, s.Schemas, s.Meta)
		}
		for _, a := range s.Attributes {
			attrs[s.Name+"."+a.Name] = a
		}
	}
	for name, check := range map[string]func(SCIMAttribute) bool{
		"User.userName":   func(a SCIMAttribute) bool { return a.Required && !a.CaseExact && a.Uniqueness == "server" },
		"User.externalId": func(a SCIMAttribute) bool { return a.CaseExact },
		"User.name":       func(a SCIMAttribute) bool { return a.Type == "complex" && len(a.SubAttributes) == 2 },
		"User.emails":     func(a SCIMAttribute) bool { return a.MultiValued && len(a.SubAttributes) == 3 },
		"User.groups": func(a SCIMAttribute) bool {
			return a.MultiValued && a.Mutability == "readOnly" && len(a.SubAttributes) == 2
		},
		"User.active":       func(a SCIMAttribute) bool { return a.Type == "boolean" },
		"Group.displayName": func(a SCIMAttribute) bool { return a.Required && !a.CaseExact && a.Uniqueness == "server" },
		"Group.members": func(a SCIMAttribute) bool {
			return a.MultiValued && len(a.SubAttributes) == 2 && a.SubAttributes[0].Mutability == "immutable"
		},
	} {
		if a, ok := attrs[name]; !ok || !check(a) {
			t.Errorf("%s = %+v", name, a)
		}
	}
	schemas[0].Meta.Location = "changed"
	if SCIMSchemas()[0].Meta.Location != "" {
		t.Fatal("SCIMSchemas must return fresh values")
	}
}
