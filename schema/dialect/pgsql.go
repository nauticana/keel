package dialect

import (
	"fmt"
	"strings"

	"github.com/nauticana/keel/schema"
)

// PgSQL implements the PostgreSQL dialect.
type PgSQL struct{}

func (d *PgSQL) Name() string { return "pgsql" }

// mapType converts abstract YAML types to PostgreSQL types.
// If the type is already PostgreSQL-native, it passes through unchanged.
func (d *PgSQL) mapType(yamlType string) string {
	upper := strings.ToUpper(yamlType)
	switch upper {
	case "BOOL":
		return "BOOLEAN"
	case "INT":
		return "INTEGER"
	case "STRING":
		// default string without size
		return "VARCHAR(255)"
	default:
		return yamlType
	}
}

func (d *PgSQL) formatDefault(col *schema.Column) string {
	if col.Default == "" {
		return ""
	}
	val := col.Default
	upper := strings.ToUpper(val)
	// PostgreSQL keywords and functions pass through as-is
	switch upper {
	case "TRUE", "FALSE", "NULL", "CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME":
		return upper
	}
	// Numeric values pass through
	if isNumeric(val) {
		return val
	}
	// Everything else is a string literal — quote it
	return "'" + strings.ReplaceAll(val, "'", "''") + "'"
}

func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	dotSeen := false
	for i, ch := range s {
		if ch == '-' && i == 0 {
			continue
		}
		if ch == '.' && !dotSeen {
			dotSeen = true
			continue
		}
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// GenerateTable emits the CREATE TABLE block plus its indexes,
// sequence, and table_sequence_usage row. Foreign keys are NOT
// emitted here — they're produced separately by GenerateForeignKeys
// after every CREATE TABLE has run, so forward references between
// tables work regardless of declaration order (P1-49).
//
// Idempotency (P1-48): every emitted statement uses IF NOT EXISTS or
// ON CONFLICT DO NOTHING, so `schemagen | psql` is safe to re-run on
// an existing database without manual cleanup.
func (d *PgSQL) GenerateTable(table *schema.Table) string {
	var sb strings.Builder

	// Comment header
	if table.Comment != "" {
		sb.WriteString(fmt.Sprintf("-- %s\n", table.Comment))
	}

	// Extensions
	for _, ext := range table.Extensions {
		sb.WriteString(fmt.Sprintf("CREATE EXTENSION IF NOT EXISTS %s;\n\n", ext))
	}

	sb.WriteString(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n", table.Name))

	// Build column lines
	var lines []string
	for _, col := range table.Columns {
		line := d.formatColumn(col)
		lines = append(lines, line)
	}

	// Primary key constraint (inline — same statement as CREATE TABLE)
	pkName := table.Name + "_pk"
	lines = append(lines, fmt.Sprintf("    CONSTRAINT %s PRIMARY KEY (%s)",
		pkName, strings.Join(table.PrimaryKey, ", ")))

	// Check constraints (inline — they reference only this table's
	// own columns, so no forward-reference hazard)
	for _, chk := range table.Checks {
		lines = append(lines, fmt.Sprintf("    CONSTRAINT %s CHECK (%s)", chk.Name, chk.Expression))
	}

	// Join lines with commas
	for i, line := range lines {
		sb.WriteString(line)
		if i < len(lines)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}

	sb.WriteString(");\n")

	// Indexes (after CREATE TABLE)
	for _, idx := range table.Indexes {
		sb.WriteString(d.formatIndex(table.Name, idx))
	}

	// Sequence + table_sequence_usage
	if table.Sequence != nil {
		sb.WriteString(fmt.Sprintf("\nCREATE SEQUENCE IF NOT EXISTS %s INCREMENT BY %d START WITH %d;\n",
			table.Sequence.Name, table.Sequence.IncrementBy, table.Sequence.StartWith))
		// ON CONFLICT DO NOTHING so a second run doesn't fail on the
		// (table_name, column_name) primary key collision.
		sb.WriteString(fmt.Sprintf("INSERT INTO table_sequence_usage (table_name, column_name, sequence_name) VALUES ('%s', '%s', '%s') ON CONFLICT DO NOTHING;\n",
			table.Name, table.Sequence.Column, table.Sequence.Name))
	}

	return sb.String()
}

// GenerateForeignKeys emits ALTER TABLE statements for every FK in
// the schema. Called by GenerateSchema AFTER every CREATE TABLE has
// run so the parent table is guaranteed to exist regardless of
// declaration order (P1-49). Each ALTER is gated by a DO block that
// adds the constraint only if it isn't already present, keeping the
// re-run-friendly contract.
func (d *PgSQL) GenerateForeignKeys(s *schema.Schema) string {
	var sb strings.Builder
	first := true
	for _, t := range s.Tables {
		for _, fk := range t.ForeignKeys {
			if first {
				sb.WriteString("\n-- Foreign keys (emitted post-CREATE so order doesn't matter)\n")
				first = false
			}
			sb.WriteString(d.formatAddForeignKey(t.Name, fk))
		}
	}
	return sb.String()
}

// formatAddForeignKey wraps an ALTER TABLE … ADD CONSTRAINT in a DO
// block that probes information_schema first. Postgres lacks an
// `ADD CONSTRAINT IF NOT EXISTS` form, so the DO block is the
// idiomatic idempotent equivalent.
func (d *PgSQL) formatAddForeignKey(tableName string, fk *schema.ForeignKey) string {
	clause := fmt.Sprintf("FOREIGN KEY (%s) REFERENCES %s(%s)",
		strings.Join(fk.Columns, ", "),
		fk.References.Table,
		strings.Join(fk.References.Columns, ", "))
	if fk.OnDelete != "" {
		clause += " ON DELETE " + strings.ToUpper(strings.TrimSpace(fk.OnDelete))
	}
	if fk.OnUpdate != "" {
		clause += " ON UPDATE " + strings.ToUpper(strings.TrimSpace(fk.OnUpdate))
	}
	return fmt.Sprintf(`DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
     WHERE constraint_name = '%s' AND table_name = '%s'
  ) THEN
    ALTER TABLE %s ADD CONSTRAINT %s %s;
  END IF;
END $$;
`, fk.Name, tableName, tableName, fk.Name, clause)
}

func (d *PgSQL) formatColumn(col *schema.Column) string {
	pgType := d.mapType(col.Type)

	// Build the column definition with aligned spacing
	nullable := "NOT NULL"
	if col.Nullable {
		nullable = ""
	}

	defVal := ""
	if col.Default != "" {
		defVal = "DEFAULT " + d.formatDefault(col)
	}

	// Build parts, then join with appropriate spacing
	// Target: "    column_name                      TYPE       NOT NULL  DEFAULT value"
	namePart := fmt.Sprintf("    %-36s %-13s", col.Name, pgType)

	var parts []string
	parts = append(parts, namePart)
	if nullable != "" {
		parts = append(parts, nullable)
	}
	if defVal != "" {
		parts = append(parts, defVal)
	}

	return strings.Join(parts, " ")
}

func (d *PgSQL) formatIndex(tableName string, idx *schema.Index) string {
	var sb strings.Builder
	if idx.Unique {
		sb.WriteString("CREATE UNIQUE INDEX IF NOT EXISTS ")
	} else {
		sb.WriteString("CREATE INDEX IF NOT EXISTS ")
	}
	sb.WriteString(idx.Name)
	sb.WriteString(" ON ")
	sb.WriteString(tableName)
	if idx.Using != "" {
		sb.WriteString(fmt.Sprintf(" USING %s", idx.Using))
	}
	sb.WriteString(fmt.Sprintf("(%s);\n", strings.Join(idx.Columns, ", ")))
	return sb.String()
}

func (d *PgSQL) GenerateSchema(s *schema.Schema) string {
	var sb strings.Builder

	sb.WriteString("-- ==========================================================================\n")
	sb.WriteString("-- Generated by schemagen — do not edit manually\n")
	sb.WriteString("-- ==========================================================================\n\n")

	for i, table := range s.Tables {
		sb.WriteString(d.GenerateTable(table))
		if i < len(s.Tables)-1 {
			sb.WriteString("\n")
		}
	}

	// Foreign keys after every table exists. See GenerateForeignKeys.
	sb.WriteString(d.GenerateForeignKeys(s))

	return sb.String()
}
