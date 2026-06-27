package pgsql

import "testing"

func TestScopePartnerFilter(t *testing.T) {
	cases := []struct {
		name       string
		where      map[string]any
		partnerID  int64
		userID     int
		globalRole bool
		want       any // expected partner_id; nil = key absent
	}{
		{"absent → caller's partner", map[string]any{}, 7, 5, false, int64(7)},
		{"matching passes", map[string]any{"partner_id": int64(7)}, 7, 5, false, int64(7)},
		{"user coerces foreign", map[string]any{"partner_id": int64(99)}, 7, 5, false, int64(7)},
		// The fix: API-key caller (userID==0, partnerID>0) supplying a foreign
		// partner_id is coerced back to its own partner — previously passed (IDOR).
		{"api-key coerces foreign", map[string]any{"partner_id": int64(99)}, 7, 0, false, int64(7)},
		{"global role passes foreign", map[string]any{"partner_id": int64(99)}, 7, 5, true, int64(99)},
		// Untrusted user with NO partner (e.g. a cross-partner rider): a supplied
		// partner_id is coerced to 0 → no rows. Must use a custom owner-scoped
		// handler instead of generic CRUD.
		{"no-partner user denied", map[string]any{"partner_id": int64(99)}, 0, 5, false, int64(0)},
		// Trusted system caller (no user AND no partner scope): honor the filter.
		{"system caller passes foreign", map[string]any{"partner_id": int64(99)}, 0, 0, false, int64(99)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scopePartnerFilter(tc.where, tc.partnerID, tc.userID, tc.globalRole)
			if got := tc.where["partner_id"]; got != tc.want {
				t.Fatalf("partner_id = %v; want %v", got, tc.want)
			}
		})
	}
}
