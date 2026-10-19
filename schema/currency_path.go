package schema

import (
	"errors"
	"fmt"
	"strings"
)

// ValidateCurrencyPaths checks every seeded column_display_attribute
// currency_path against the YAML schema: the money column is a BIGINT and the
// path's parent-table segments each have one foreign key from the previous
// table, and the last table holds the column the last segment names. A role
// granted TABLE SELECT on the money table must hold it on each table of the
// path and on currency, which the client reads to format the amount.
func ValidateCurrencyPaths(seeds []*SeedFile, s *Schema) error {
	reads := tableSelects(seeds)
	needs := map[string]map[string]bool{}
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
					continue
				}
				if needs[table] == nil {
					needs[table] = map[string]bool{"currency": true}
				}
				parts := strings.Split(path, ".")
				for _, name := range parts[:len(parts)-1] {
					needs[table][name] = true
				}
			}
		}
	}
	for table, names := range needs {
		for role := range reads[table] {
			for name := range names {
				if !reads[name][role] && !reads["*"][role] {
					errs = append(errs, fmt.Errorf("seed: %s reads money table %s but has no TABLE SELECT on %s", role, table, name))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// tableSelects maps each table (or "*") to the roles seeded with TABLE SELECT on it.
func tableSelects(seeds []*SeedFile) map[string]map[string]bool {
	reads := map[string]map[string]bool{}
	for _, sf := range seeds {
		for _, st := range sf.Seeds {
			ri, oi, ai, li := seedColumn(st, "role_id"), seedColumn(st, "authorization_object_id"), seedColumn(st, "action"), seedColumn(st, "low_limit")
			if st.Table != "authorization_role_permission" || ri < 0 || oi < 0 || ai < 0 || li < 0 {
				continue
			}
			for _, row := range st.Rows {
				if fmt.Sprint(row[oi]) != "TABLE" || fmt.Sprint(row[ai]) != "SELECT" {
					continue
				}
				table := fmt.Sprint(row[li])
				if reads[table] == nil {
					reads[table] = map[string]bool{}
				}
				reads[table][fmt.Sprint(row[ri])] = true
			}
		}
	}
	return reads
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
