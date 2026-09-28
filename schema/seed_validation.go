package schema

import (
	"errors"
	"fmt"
	"strings"
)

// ValidateSeeds checks that every seeded foreign-key value matches a seeded
// row of the referenced table, so a fresh load cannot fail on an FK.
func ValidateSeeds(seeds []*SeedFile, s *Schema) error {
	rows := map[string][]map[string]any{}
	for _, sf := range seeds {
		for _, st := range sf.Seeds {
			for i, row := range st.Rows {
				if len(row) != len(st.Columns) {
					return fmt.Errorf("seed: %s row %d has %d values for %d columns", st.Table, i, len(row), len(st.Columns))
				}
				values := make(map[string]any, len(row))
				for c, v := range row {
					values[st.Columns[c]] = v
				}
				rows[st.Table] = append(rows[st.Table], values)
			}
		}
	}
	keys := map[string]map[string]bool{}
	keyOf := func(values map[string]any, columns []string) (string, bool) {
		parts := make([]string, len(columns))
		for i, c := range columns {
			v, ok := values[c]
			if !ok || v == nil {
				return "", false
			}
			parts[i] = fmt.Sprint(v)
		}
		return strings.Join(parts, "\x00"), true
	}
	var errs []error
	for table, tableRows := range rows {
		t := s.GetTable(table)
		if t == nil {
			errs = append(errs, fmt.Errorf("seed: unknown table %s", table))
			continue
		}
		for _, fk := range t.ForeignKeys {
			index := fk.Name + "\x00" + fk.References.Table
			if keys[index] == nil {
				keys[index] = map[string]bool{}
				for _, parent := range rows[fk.References.Table] {
					if k, ok := keyOf(parent, fk.References.Columns); ok {
						keys[index][k] = true
					}
				}
			}
			for _, row := range tableRows {
				if k, ok := keyOf(row, fk.Columns); ok && !keys[index][k] {
					errs = append(errs, fmt.Errorf("seed: %s.%v = %s has no seeded %s row (FK %s)",
						table, fk.Columns, strings.ReplaceAll(k, "\x00", ","), fk.References.Table, fk.Name))
				}
			}
		}
	}
	return errors.Join(errs...)
}
