package model

import (
	"fmt"
	"strconv"
	"time"
)

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

// Into fills targets from the leading columns in order, each converted by
// Coerce; a nullable column takes a pointer-to-pointer target.
func (r Row) Into(targets ...any) error {
	if len(targets) > len(r.values) {
		return fmt.Errorf("%w: %d targets for %d columns", ErrColumnNotFound, len(targets), len(r.values))
	}
	for j, target := range targets {
		if err := assign(target, r.values[j]); err != nil {
			name := strconv.Itoa(j)
			if j < len(r.columns) {
				name = r.columns[j]
			}
			return fmt.Errorf("column %s: %w", name, err)
		}
	}
	return nil
}

func assign(target, v any) error {
	switch p := target.(type) {
	case *int64:
		return set(p, v)
	case *int32:
		return set(p, v)
	case *int:
		return set(p, v)
	case *float64:
		return set(p, v)
	case *bool:
		return set(p, v)
	case *string:
		return set(p, v)
	case *time.Time:
		return set(p, v)
	case *[]byte:
		return set(p, v)
	case *any:
		return set(p, v)
	case **int64:
		return set(p, v)
	case **int32:
		return set(p, v)
	case **int:
		return set(p, v)
	case **float64:
		return set(p, v)
	case **bool:
		return set(p, v)
	case **string:
		return set(p, v)
	case **time.Time:
		return set(p, v)
	case **[]byte:
		return set(p, v)
	case **any:
		return set(p, v)
	}
	return fmt.Errorf("%w: unsupported target %T", ErrCoercion, target)
}

func set[T any](p *T, v any) error {
	if p == nil {
		return fmt.Errorf("%w: nil target", ErrCoercion)
	}
	out, err := Coerce[T](v)
	if err == nil {
		*p = out
	}
	return err
}
