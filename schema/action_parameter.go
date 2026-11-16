package schema

import (
	"errors"
	"fmt"
	"slices"
)

// ValidateActionParameters rejects a table_action_parameter named like a key
// column of its table or like another parameter of the same action: the REST
// loader merges both into one POST body and refuses such metadata at start.
func ValidateActionParameters(seeds []*SeedFile, s *Schema) error {
	seen := map[[3]string]bool{}
	var errs []error
	for _, sf := range seeds {
		for _, st := range sf.Seeds {
			if st.Table != "table_action_parameter" {
				continue
			}
			tableCol, actionCol, nameCol := slices.Index(st.Columns, "table_name"), slices.Index(st.Columns, "action_name"), slices.Index(st.Columns, "param_name")
			if tableCol < 0 || actionCol < 0 || nameCol < 0 {
				errs = append(errs, errors.New("seed: table_action_parameter needs table_name, action_name and param_name"))
				continue
			}
			for _, row := range st.Rows {
				if len(row) != len(st.Columns) {
					continue
				}
				key := [3]string{fmt.Sprint(row[tableCol]), fmt.Sprint(row[actionCol]), fmt.Sprint(row[nameCol])}
				if t := s.GetTable(key[0]); t != nil && slices.Contains(t.PrimaryKey, key[2]) {
					errs = append(errs, fmt.Errorf("seed: table_action_parameter %s.%s.%s is named like a key column of %s", key[0], key[1], key[2], key[0]))
				}
				if seen[key] {
					errs = append(errs, fmt.Errorf("seed: table_action_parameter %s.%s.%s is declared twice", key[0], key[1], key[2]))
				}
				seen[key] = true
			}
		}
	}
	return errors.Join(errs...)
}
