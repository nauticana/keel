package handler

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/document"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/authserver"
	"github.com/nauticana/keel/payout"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

var updateWire = flag.Bool("update-wire", false, "rewrite testdata/wire_contract.json from the current response types")

// wireTypes are the typed bodies handlers answer with; their JSON members are clients' contract.
var wireTypes = []any{
	authserver.Grant{},
	billing.Invoice{},
	billing.Plan{},
	billing.Subscription{},
	document.PartnerDocument{},
	model.AgencyEarnings{},
	model.AgencyInvite{},
	model.PasswordPolicyView{},
	model.UserMenu{},
	otpSendResponse{},
	payout.Instruction{},
	payout.StartOnboardingResult{},
	port.InboxPage{},
	user.ActiveSession{},
	user.Member{},
	user.PartnerCreated{},
	user.PublicPlan{},
	user.TrustedDevice{},
}

// TestWireContract fails when a response member is renamed, removed, added or
// retyped. Such a change is breaking for installed clients: list it under
// "Wire" in the migration guide, then rerun with -update-wire.
func TestWireContract(t *testing.T) {
	shapes := map[string]any{}
	for _, v := range wireTypes {
		typ := reflect.TypeOf(v)
		shapes[typ.String()] = wireShape(typ, map[reflect.Type]bool{})
	}
	got, err := json.MarshalIndent(shapes, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	const golden = "testdata/wire_contract.json"
	if *updateWire {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("a response shape changed; a renamed, removed or retyped member breaks installed clients. List it under Wire in migration_guide.json and rerun with -update-wire.\n%s", got)
	}
}

// wireShape is the JSON shape of typ: member name to shape for an object, a
// one-element list for an array, and the JSON type name otherwise.
func wireShape(typ reflect.Type, seen map[reflect.Type]bool) any {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeFor[time.Time]() || typ.Implements(reflect.TypeFor[json.Marshaler]()) {
		return typ.String()
	}
	switch typ.Kind() {
	case reflect.Slice, reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			return "base64"
		}
		return []any{wireShape(typ.Elem(), seen)}
	case reflect.Map:
		return map[string]any{"*": wireShape(typ.Elem(), seen)}
	case reflect.Struct:
		if seen[typ] {
			return typ.String()
		}
		seen[typ] = true
		defer delete(seen, typ)
		members := map[string]any{}
		for f := range typ.Fields() {
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" && opts == "" || !f.IsExported() && !f.Anonymous {
				continue
			}
			if f.Anonymous && name == "" {
				if inner, ok := wireShape(f.Type, seen).(map[string]any); ok {
					for k, v := range inner {
						members[k] = v
					}
					continue
				}
			}
			if name == "" {
				name = f.Name
			}
			if strings.Contains(opts, "string") {
				members[name] = "string"
			} else {
				members[name] = wireShape(f.Type, seen)
			}
		}
		return members
	case reflect.Bool:
		return "boolean"
	case reflect.String:
		return "string"
	case reflect.Interface:
		return "any"
	default:
		return "number"
	}
}
