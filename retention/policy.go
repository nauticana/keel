// Package retention deletes rows of a table once they pass an age, for data
// kept for a fixed period without an account to erase it through.
package retention

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

const batchSize = 500

var (
	ErrPolicy  = errors.New("retention: invalid policy")
	identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
)

// Policy deletes the rows of Table whose AgeColumn is older than Window. Child
// tables must cascade, or be listed earlier with their own policy.
type Policy struct {
	Table     string
	AgeColumn string        // a timestamp column of Table
	Window    time.Duration // must be positive
	Batch     int           // rows per DELETE; zero is 500
}

// query validates the policy against the loaded schema and returns its DELETE.
func (p Policy) query(db port.DatabaseRepository) (string, error) {
	if p.Window <= 0 || p.Batch < 0 {
		return "", fmt.Errorf("%w: %s needs a positive window and a non-negative batch", ErrPolicy, p.Table)
	}
	if !identifier.MatchString(p.Table) || !identifier.MatchString(p.AgeColumn) {
		return "", fmt.Errorf("%w: invalid table or column", ErrPolicy)
	}
	table := db.GetTableDefinition(p.Table)
	if table == nil {
		return "", fmt.Errorf("%w: unknown table %q", ErrPolicy, p.Table)
	}
	if !slices.ContainsFunc(table.Columns, func(c *model.TableColumn) bool {
		return c.ColumnName == p.AgeColumn && c.DataType == model.DT_TIME
	}) {
		return "", fmt.Errorf("%w: %s has no timestamp column %q", ErrPolicy, p.Table, p.AgeColumn)
	}
	if len(table.Keys) == 0 {
		return "", fmt.Errorf("%w: %s has no key for batched deletion", ErrPolicy, p.Table)
	}
	keys := make([]string, len(table.Keys))
	for i, key := range table.Keys {
		if key == nil || !identifier.MatchString(key.ColumnName) {
			return "", fmt.Errorf("%w: %s has an invalid key column", ErrPolicy, p.Table)
		}
		keys[i] = key.ColumnName
	}
	keyList := strings.Join(keys, ", ")
	return fmt.Sprintf("DELETE FROM %[1]s WHERE (%[3]s) IN (SELECT * FROM (SELECT %[3]s FROM %[1]s WHERE %[2]s < ? LIMIT ?) AS expired) RETURNING 1",
		p.Table, p.AgeColumn, keyList), nil
}

func (p Policy) batch() int {
	if p.Batch == 0 {
		return batchSize
	}
	return p.Batch
}
