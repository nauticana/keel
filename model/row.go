package model

import "fmt"

// Row is one row of a QueryResult, read by column position (At) or name (Get).
type Row struct {
	columns []string
	values  []any
}

// Value returns the value of the named column, or ErrColumnNotFound.
func (r Row) Value(name string) (any, error) {
	for i, col := range r.columns {
		if col == name && i < len(r.values) {
			return r.values[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrColumnNotFound, name)
}

// Get returns the named column converted by Coerce.
func (r Row) Get[T any](name string) (T, error) {
	v, err := r.Value(name)
	if err != nil {
		var zero T
		return zero, err
	}
	return Coerce[T](v)
}

// At returns column j converted by Coerce, without a name lookup.
func (r Row) At[T any](j int) (T, error) {
	if j < 0 || j >= len(r.values) {
		var zero T
		return zero, fmt.Errorf("%w: index %d", ErrColumnNotFound, j)
	}
	return Coerce[T](r.values[j])
}
