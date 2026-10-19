package schema

import (
	"errors"
	"fmt"
	"strings"
)

// ValidateCurrencyPaths checks every seeded column_display_attribute
// currency_path against the YAML schema: the money column is a BIGINT and the
// path's parent-table segments each have one foreign key from the previous
// table, and the last table holds the column the last segment names.
func ValidateCurrencyPaths(seeds []*SeedFile, s *Schema) error {
	var errs []error
	for _, sf := range seeds {
		for _, st := range sf.Seeds {
			ti, ci, pi := seedColumn(st, "table_name"), seedColumn(st, "column_name"), seedColumn(st, "currency_path")
			if st.Table != "column_display_attribute" || pi < 0 {
				continue
			}
			for _, row := range st.Rows {
				if row[pi] == nil {
					continue
				}
				table, column, path := fmt.Sprint(row[ti]), fmt.Sprint(row[ci]), fmt.Sprint(row[pi])
				if err := checkCurrencyPath(s, table, column, path); err != nil {
					errs = append(errs, fmt.Errorf("seed: column_display_attribute %s.%s currency_path %q: %w", table, column, path, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

func checkCurrencyPath(s *Schema, tableName, column, path string) error {
	t := s.GetTable(tableName)
	if t == nil {
		return fmt.Errorf("unknown table")
	}
	c := t.Column(column)
	if c == nil {
		return fmt.Errorf("unknown column")
	}
	if !strings.HasPrefix(strings.ToUpper(c.Type), "BIGINT") {
		return fmt.Errorf("money column is %s, not BIGINT", c.Type)
	}
	parts := strings.Split(path, ".")
	for _, name := range parts[:len(parts)-1] {
		links := 0
		for _, f := range t.ForeignKeys {
			if f.References.Table == name {
				links++
			}
		}
		if links != 1 {
			return fmt.Errorf("%s has %d foreign keys to %s, need one", t.Name, links, name)
		}
		if t = s.GetTable(name); t == nil {
			return fmt.Errorf("unknown table %s", name)
		}
	}
	if t.Column(parts[len(parts)-1]) == nil {
		return fmt.Errorf("%s has no column %s", t.Name, parts[len(parts)-1])
	}
	return nil
}

// Column returns the column named name, or nil.
func (t *Table) Column(name string) *Column {
	for _, c := range t.Columns {
		if c.Name == name {
			return c
		}
	}
	return nil
}
