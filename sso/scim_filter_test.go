package sso

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nauticana/keel/config"
)

func renderDNF(f scimFilter) string {
	terms := make([]string, 0, len(f.terms))
	for _, term := range f.terms {
		parts := make([]string, 0, len(term))
		for _, c := range term {
			not := ""
			if c.negate {
				not = "!"
			}
			parts = append(parts, fmt.Sprintf("%s%s %s %q", not, c.attr, c.op, c.value))
		}
		terms = append(terms, strings.Join(parts, " & "))
	}
	return strings.Join(terms, " | ")
}

func TestParseSCIMFilter(t *testing.T) {
	for filter, want := range map[string]string{
		``:                  ``,
		`userName eq "Ada"`: `username eq "ada"`,
		`USERNAME EQ "Ada"`: `username eq "ada"`,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "A"`: `username eq "a"`,
		`id eq "5"`:           `id eq "5"`,
		`externalId eq "AbC"`: `externalid eq "AbC"`,
		`externalId pr`:       `externalid pr ""`,
		`userName ne "a"`:     `username ne "a"`,
		`userName co "a" and externalId sw "X" and userName ew "z"`: `username co "a" & externalid sw "X" & username ew "z"`,
		`userName eq "a" or userName eq "b"`:                        `username eq "a" | username eq "b"`,
		`not (userName eq "a" or externalId pr)`:                    `!username eq "a" & !externalid pr ""`,
		`not (userName eq "a" and externalId pr)`:                   `!username eq "a" | !externalid pr ""`,
		`(userName co "a" or userName ew "b") and id ne "3"`:        `username co "a" & id ne "3" | username ew "b" & id ne "3"`,
		`userName eq "a' OR '1'='1"`:                                `username eq "a' or '1'='1"`,
		`userName eq "\"quoted\" A"`:                                `username eq "\"quoted\" a"`,
		`not (not (userName eq "a"))`:                               `username eq "a"`,
	} {
		f, err := parseSCIMFilter(filter, scimUserFilterSchema)
		if err != nil || renderDNF(f) != want {
			t.Errorf("%s = %s %v, want %s", filter, renderDNF(f), err, want)
		}
	}
	if f, err := parseSCIMFilter(`DisplayName eq "Admins" or urn:ietf:params:scim:schemas:core:2.0:Group:externalId eq "X"`, scimGroupFilterSchema); err != nil ||
		renderDNF(f) != `displayname eq "admins" | externalid eq "X"` {
		t.Errorf("group filter = %s %v", renderDNF(f), err)
	}
}

func TestParseSCIMFilterRefusals(t *testing.T) {
	explosive := strings.Repeat(`(userName eq "a" or userName eq "b") and `, 6) + `userName pr`
	tooMany := strings.Repeat(`userName eq "a" or `, scimFilterMaxComparisons) + `userName pr`
	for name, filter := range map[string]string{
		"unknown attribute":       `title eq "x"`,
		"other schema":            `urn:ietf:params:scim:schemas:core:2.0:Group:userName eq "x"`,
		"ordering operator":       `userName gt "a"`,
		"unknown operator":        `userName like "a"`,
		"number value":            `userName eq 5`,
		"boolean value":           `userName eq true`,
		"missing value":           `userName eq`,
		"dangling and":            `userName eq "a" and`,
		"unclosed parenthesis":    `(userName eq "a"`,
		"extra parenthesis":       `userName eq "a")`,
		"not without parentheses": `not userName eq "a"`,
		"value path":              `emails[type eq "work"]`,
		"sub-attribute":           `name.givenName eq "a"`,
		"statement separator":     `userName eq "a"; DROP TABLE partner_scim_user`,
		"single quotes":           `userName eq 'a'`,
		"comment":                 `userName eq "a" -- x`,
		"unterminated string":     `userName eq "a`,
		"bad escape":              `userName eq "\x"`,
		"long value":              `userName eq "` + strings.Repeat("a", scimFilterMaxValue+1) + `"`,
		"long filter":             `userName eq "a"` + strings.Repeat(" ", scimFilterMaxLength),
		"too many comparisons":    tooMany,
		"too many terms":          explosive,
	} {
		if _, err := parseSCIMFilter(filter, scimUserFilterSchema); !errors.Is(err, ErrSCIMInvalidFilter) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, filter := range []string{`members[value eq "1"]`, `members.value eq "1"`, `members eq "1"`} {
		if _, err := parseSCIMFilter(filter, scimGroupFilterSchema); !errors.Is(err, ErrSCIMInvalidFilter) {
			t.Errorf("group %s: %v", filter, err)
		}
	}
}

func TestSCIMFilterArgs(t *testing.T) {
	args := func(filter string) []any {
		f, err := parseSCIMFilter(filter, scimUserFilterSchema)
		if err != nil {
			t.Fatal(err)
		}
		return f.args(7, scimUserFilterSchema)
	}
	none := []any{int64(7), int64(0), int64(0), "", "", "", "", 0, []int64(nil), []string(nil), []string(nil), []bool(nil), []string(nil)}
	if got := args(""); !reflect.DeepEqual(got, none) {
		t.Errorf("empty = %v", got)
	}
	if got := args(`userName eq "Ada"`); got[3] != "ada" || got[4] != "ada" || got[7] != 0 {
		t.Errorf("key equality must use the indexed parameter: %v", got)
	}
	if got := args(`id eq "9" and externalId eq "X" and userName co "d"`); got[1] != int64(9) || got[5] != "X" || got[7] != 1 ||
		!reflect.DeepEqual(got[9], []string{"username"}) {
		t.Errorf("mixed term = %v", got)
	}
	if got := args(`id eq "abc"`); got[1] != int64(0) || got[7] != 1 || !reflect.DeepEqual(got[12], []string{"abc"}) {
		t.Errorf("a non-numeric id must stay a comparison: %v", got)
	}
	got := args(`userName eq "a" or externalId eq "b' OR 1=1"`)
	if got[3] != "" || got[7] != 2 || !reflect.DeepEqual(got[8], []int64{0, 1}) || !reflect.DeepEqual(got[12], []string{"a", "b' OR 1=1"}) {
		t.Errorf("disjunction = %v", got)
	}
	for _, q := range []string{qSCIMUsers, qSCIMUserCount, qSCIMGroups, qSCIMGroupCount} {
		if n := strings.Count(scimQueries[q], "?"); n < len(none) {
			t.Errorf("%s has %d placeholders for %d filter arguments", q, n, len(none))
		}
	}
}

func TestListFiltersAndPages(t *testing.T) {
	p, _ := newProvisioning(t)
	ctx := context.Background()
	for _, name := range []string{"ada", "bob", "carl"} {
		if _, err := p.CreateUser(ctx, acme, scimUser(name+"@acme.example", name+"@acme.example", true)); err != nil {
			t.Fatal(err)
		}
	}
	count := func(filter string) int {
		list, err := p.ListUsers(ctx, acme, SCIMListQuery{Filter: filter})
		if err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
		return list.TotalResults
	}
	for filter, want := range map[string]int{
		`userName sw "A" or userName sw "b"`:                     2,
		`not (userName eq "ADA@acme.example")`:                   2,
		`externalId eq "ext-bob@acme.example"`:                   1,
		`externalId eq "EXT-BOB@acme.example"`:                   0,
		`userName ew "example" and not (externalId co "carl")`:   2,
		`userName eq "x' OR '1'='1"`:                             0,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName pr`: 3,
	} {
		if got := count(filter); got != want {
			t.Errorf("%s = %d, want %d", filter, got, want)
		}
	}
	zero := 0
	list, err := p.ListUsers(ctx, acme, SCIMListQuery{Count: &zero})
	if err != nil || list.TotalResults != 3 || len(list.Resources) != 0 || list.ItemsPerPage != 0 {
		t.Fatalf("count=0 = %+v %v", list, err)
	}
	list, err = p.ListUsers(ctx, acme, SCIMListQuery{StartIndex: -4})
	if err != nil || list.StartIndex != 1 || len(list.Resources) != 3 {
		t.Fatalf("default count = %+v %v", list, err)
	}

	if _, err := p.CreateGroup(ctx, acme, &SCIMGroup{DisplayName: "Admins"}); err != nil {
		t.Fatal(err)
	}
	groups, err := p.ListGroups(ctx, acme, SCIMListQuery{Filter: `displayName eq "ADMINS"`})
	if err != nil || groups.TotalResults != 1 {
		t.Fatalf("displayName is not caseExact: %+v %v", groups, err)
	}
	if _, err := p.CreateGroup(ctx, acme, &SCIMGroup{DisplayName: "admins"}); !errors.Is(err, ErrSCIMConflict) {
		t.Fatalf("displayName differing only in case = %v", err)
	}
	if _, err := p.ListGroups(ctx, acme, SCIMListQuery{Filter: `members[value eq "1"]`}); !errors.Is(err, ErrSCIMInvalidFilter) {
		t.Fatalf("members filter = %v", err)
	}
}

func TestPage(t *testing.T) {
	n := func(v int) *int { return &v }
	def, max := 25, 100
	savedDefault, savedMax := config.Config().DefaultListPageSize, config.Config().MaxListPageSize
	config.Config().DefaultListPageSize, config.Config().MaxListPageSize = def, max
	t.Cleanup(func() { config.Config().DefaultListPageSize, config.Config().MaxListPageSize = savedDefault, savedMax })
	for _, c := range []struct {
		q                SCIMListQuery
		start, wantCount int
	}{
		{SCIMListQuery{}, 1, def},
		{SCIMListQuery{StartIndex: -3, Count: n(-1)}, 1, 0},
		{SCIMListQuery{StartIndex: 0, Count: n(0)}, 1, 0},
		{SCIMListQuery{StartIndex: 7, Count: n(5)}, 7, 5},
		{SCIMListQuery{Count: n(max + 1)}, 1, max},
	} {
		if start, count := page(c.q); start != c.start || count != c.wantCount {
			t.Errorf("%+v = %d %d", c.q, start, count)
		}
	}
}
