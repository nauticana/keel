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
		{"SELECT 'it''s ?' , ?", "SELECT 'it''s ?' , $1"},
		{`SELECT E'it\'s ?' , ?`, `SELECT E'it\'s ?' , $1`},
		{`SELECT "col?" FROM t WHERE a = ?`, `SELECT "col?" FROM t WHERE a = $1`},
		{"SELECT 1 -- why?\n WHERE a = ?", "SELECT 1 -- why?\n WHERE a = $1"},
		{"SELECT /* a? /* nested? */ b? */ ?", "SELECT /* a? /* nested? */ b? */ $1"},
		{"SELECT $fn$ body ? $fn$, ?", "SELECT $fn$ body ? $fn$, $1"},
		{"SELECT $$ ? $$, ?", "SELECT $$ ? $$, $1"},
		{"SELECT $1$ + ?", "SELECT $1$ + $1"},
	}
	for _, c := range cases {
		if got := RewritePlaceholders(c.in); got != c.want {
			t.Errorf("RewritePlaceholders(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
