package dialect

import (
	"strings"

	"github.com/nauticana/keel/schema"
)

// Dialect generates SQL DDL for a specific database engine.
type Dialect interface {
	// Name returns the dialect identifier (e.g., "pgsql", "mysql").
	Name() string

	// GenerateTable produces the CREATE TABLE statement for a single table.
	GenerateTable(table *schema.Table) string

	// GenerateSchema produces the full DDL for all tables, sequences, and indexes.
	GenerateSchema(s *schema.Schema) string
}

// commentBlock prefixes every line of a (possibly multi-line) YAML
// comment with `-- ` so the emitted SQL is parseable. Without per-line
// prefixing, the second line of a multi-line comment becomes unquoted
// text and the DB rejects the file with a syntax error. Trailing
// newlines on the input are trimmed; the returned string ends with one
// newline so the caller can concatenate it directly.
func commentBlock(comment string) string {
	if comment == "" {
		return ""
	}
	comment = strings.TrimRight(comment, "\n")
	lines := strings.Split(comment, "\n")
	var b strings.Builder
	for _, line := range lines {
		b.WriteString("-- ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
