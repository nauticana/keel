package pgsql

import "testing"

func TestRewritePlaceholders(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT * FROM t WHERE a = ? AND b = ?", "SELECT * FROM t WHERE a = $1 AND b = $2"},
		// ?? escapes to a literal ? so jsonb operators survive.
		{"SELECT * FROM t WHERE data ?? 'k'", "SELECT * FROM t WHERE data ? 'k'"},
		{"SELECT * FROM t WHERE tags ??| ? ", "SELECT * FROM t WHERE tags ?| $1 "},
		// ? inside a string literal is untouched.
		{"SELECT '?' , ?", "SELECT '?' , $1"},
	}
	for _, c := range cases {
		if got := rewritePlaceholders(c.in); got != c.want {
			t.Errorf("rewritePlaceholders(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
