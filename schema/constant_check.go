package schema

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var checkCodes = regexp.MustCompile(`'([^']*)'`)

// ValidateConstantChecks requires every column a constant_lookup seed row maps
// to carry a CHECK of the form "column IN (...)" listing exactly that domain's
// constant_value codes, so a code added to one place cannot drift from the other.
func ValidateConstantChecks(seeds []*SeedFile, s *Schema) error {
	codes := map[string][]string{}
	var lookups [][]any
	for _, sf := range seeds {
		for _, st := range sf.Seeds {
			switch st.Table {
			case "constant_value":
				id, value := seedColumn(st, "constant_id"), seedColumn(st, "value")
				for _, r := range st.Rows {
					if id >= 0 && value >= 0 {
						codes[fmt.Sprint(r[id])] = append(codes[fmt.Sprint(r[id])], fmt.Sprint(r[value]))
					}
				}
			case "constant_lookup":
				c, t, col := seedColumn(st, "constant_id"), seedColumn(st, "table_name"), seedColumn(st, "column_name")
				for _, r := range st.Rows {
					if c >= 0 && t >= 0 && col >= 0 {
						lookups = append(lookups, []any{r[c], r[t], r[col]})
					}
				}
			}
		}
	}
	var errs []error
	for _, l := range lookups {
		constant, table, column := fmt.Sprint(l[0]), fmt.Sprint(l[1]), fmt.Sprint(l[2])
		want := codes[constant]
		if len(want) == 0 {
			errs = append(errs, fmt.Errorf("seed: constant_lookup %s.%s maps constant %s, which has no constant_value rows in the given seeds", table, column, constant))
			continue
		}
		t := s.GetTable(table)
		if t == nil {
			continue // ValidateSeeds reports the unknown table
		}
		var listed []string
		for _, c := range t.Checks {
			if strings.HasPrefix(c.Expression, column+" IN (") {
				for _, m := range checkCodes.FindAllStringSubmatch(c.Expression, -1) {
					listed = append(listed, m[1])
				}
			}
		}
		if listed == nil {
			errs = append(errs, fmt.Errorf("seed: %s.%s maps constant %s but has no CHECK \"%s IN (...)\"", table, column, constant, column))
			continue
		}
		want = append([]string(nil), want...)
		sort.Strings(listed)
		sort.Strings(want)
		if strings.Join(listed, ",") != strings.Join(want, ",") {
			errs = append(errs, fmt.Errorf("seed: %s.%s CHECK lists %v, constant %s has %v", table, column, listed, constant, want))
		}
	}
	return errors.Join(errs...)
}

func seedColumn(st *SeedTable, name string) int {
	for i, c := range st.Columns {
		if c == name {
			return i
		}
	}
	return -1
}
