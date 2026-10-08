package model

import "testing"

func TestPrincipalValid(t *testing.T) {
	for name, tc := range map[string]struct {
		p    Principal
		want bool
	}{
		"zero":  {Principal{}, false},
		"no id": {Principal{Kind: PrincipalUser}, false},
		"user":  {UserPrincipal(7), true},
		"role":  {RolePrincipal("PARTNER_OPER"), true},
	} {
		if got := tc.p.Valid(); got != tc.want {
			t.Errorf("%s: Valid() = %v, want %v", name, got, tc.want)
		}
	}
	if p := RolePrincipal("PARTNER_OPER"); p.Kind != PrincipalRole || p.ID != "PARTNER_OPER" {
		t.Errorf("RolePrincipal = %+v", p)
	}
}
