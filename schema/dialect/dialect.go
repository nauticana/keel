package dialect

import (
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
