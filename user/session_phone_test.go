package user

import (
	"strings"
	"testing"
)

// selectColumns returns the SELECT list of a named query, with table
// aliases stripped: "SELECT t.user_id, U.phone FROM ..." -> [user_id phone].
func selectColumns(t *testing.T, sql string) []string {
	t.Helper()
	upper := strings.ToUpper(sql)
	start := strings.Index(upper, "SELECT ")
	if start < 0 {
		t.Fatalf("no SELECT in %q", sql)
	}
	rest := sql[start+len("SELECT "):]
	end := strings.Index(strings.ToUpper(rest), " FROM")
	if end < 0 {
		t.Fatalf("no FROM in %q", sql)
	}
	var cols []string
	for _, c := range strings.Split(rest[:end], ",") {
		c = strings.TrimSpace(c)
		if i := strings.LastIndex(c, "."); i >= 0 {
			c = c[i+1:]
		}
		cols = append(cols, c)
	}
	return cols
}

// Every query behind a session builder must select phone at the exact
// offset that builder reads, or PhoneFor silently resolves "" and the
// SMS channel becomes a no-op for every user.
func TestSessionQueriesSelectPhoneAtExpectedIndex(t *testing.T) {
	for _, tc := range []struct {
		query    string
		index    int
		consumer string
	}{
		{qUserById, 11, "GetUserById"},
		{qUserByLogin, 11, "GetUserByLogin / GetUserByUsername"},
		{qUserByLoginEmail, 11, "GetUserByLogin / GetUserByUsername"},
		{qPartnerUserByEmail, 11, "GetUserByEmail"},
		{qGetRefreshToken, 7, "ValidateRefreshToken"},
		{qUserByPhone, 4, "getUserByPhone"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			sql, ok := LocalUserQueries[tc.query]
			if !ok {
				t.Fatalf("%s missing from LocalUserQueries", tc.query)
			}
			cols := selectColumns(t, sql)
			if tc.index >= len(cols) {
				t.Fatalf("%s selects %d columns, %s reads row[%d]", tc.query, len(cols), tc.consumer, tc.index)
			}
			if cols[tc.index] != "phone" {
				t.Errorf("%s: row[%d] = %q, want phone (%s reads it there); columns: %v",
					tc.query, tc.index, cols[tc.index], tc.consumer, cols)
			}
		})
	}
}
