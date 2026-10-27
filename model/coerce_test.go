package model

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"
)

func TestCoerce(t *testing.T) {
	now := time.Now()
	check := func(name string, got, want any, err error) {
		t.Helper()
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", name, got, err, want)
		}
	}
	n64, err := Coerce[int64](int16(7))
	check("int64", n64, int64(7), err)
	n32, err := Coerce[int32](json.Number("12"))
	check("int32", n32, int32(12), err)
	n, err := Coerce[int](float64(3))
	check("int", n, 3, err)
	f, err := Coerce[float64](int64(2))
	check("float64", f, 2.0, err)
	b, err := Coerce[bool](int64(1))
	check("bool", b, true, err)
	if b, ok := BoolOf(uint64(math.MaxUint64)); !ok || !b {
		t.Errorf("BoolOf(uint64 max) = %v, %v", b, ok)
	}
	s, err := Coerce[string](int64(5))
	check("string", s, "5", err)
	tm, err := Coerce[time.Time](now)
	check("time", tm, now, err)
	raw, err := Coerce[[]byte]("ab")
	check("bytes", string(raw), "ab", err)
	a, err := Coerce[any](nil)
	check("any", a, nil, err)

	if p, err := Coerce[*int64](nil); p != nil || err != nil {
		t.Errorf("*int64 NULL = %v, %v", p, err)
	}
	if p, err := Coerce[*string]("x"); err != nil || *p != "x" {
		t.Errorf("*string = %v, %v", p, err)
	}
	if p, err := Coerce[*any](nil); err != nil || p != nil {
		t.Errorf("*any NULL = %v, %v", p, err)
	}
	if p, err := Coerce[*any]("x"); err != nil || p == nil || *p != "x" {
		t.Errorf("*any = %v, %v", p, err)
	}
	if _, err := Coerce[int64](nil); !errors.Is(err, ErrNullValue) {
		t.Errorf("NULL int64: %v", err)
	}
	for name, err := range map[string]error{
		"fraction":  second(Coerce[int64](1.5)),
		"overflow":  second(Coerce[int32](int64(math.MaxInt32) + 1)),
		"type":      second(Coerce[time.Time](int64(1))),
		"bytes":     second(Coerce[[]byte](int64(1))),
		"ptr inner": second(Coerce[*int64]("x")),
	} {
		if !errors.Is(err, ErrCoercion) {
			t.Errorf("%s: %v, want ErrCoercion", name, err)
		}
	}
}

func second[T any](_ T, err error) error { return err }

func TestQueryResultRows(t *testing.T) {
	qr := &QueryResult{Columns: []string{"id", "name", "deleted_at"}, Rows: [][]any{{int64(1), "a", nil}, {int64(2), "b", nil}}}
	if id, err := qr.Col[int64](1, "id"); err != nil || id != 2 {
		t.Fatalf("Col = %d, %v", id, err)
	}
	if _, err := qr.Col[int64](2, "id"); !errors.Is(err, ErrRowOutOfRange) {
		t.Errorf("row 2: %v", err)
	}
	if _, err := qr.Col[int64](0, "nope"); !errors.Is(err, ErrColumnNotFound) {
		t.Errorf("missing column: %v", err)
	}
	row, err := qr.Row(0)
	if err != nil {
		t.Fatal(err)
	}
	if name, err := row.At[string](1); err != nil || name != "a" {
		t.Errorf("At(1) = %q, %v", name, err)
	}
	if _, err := row.At[int64](3); !errors.Is(err, ErrColumnNotFound) {
		t.Errorf("At(3): %v", err)
	}
	if deleted, err := row.Get[*time.Time]("deleted_at"); err != nil || deleted != nil {
		t.Errorf("NULL pointer = %v, %v", deleted, err)
	}
	names, err := qr.Scan[string](func(r Row) (string, error) { return r.Get[string]("name") })
	if err != nil || len(names) != 2 || names[1] != "b" {
		t.Fatalf("Scan = %v, %v", names, err)
	}
	if _, err := qr.Scan[time.Time](func(r Row) (time.Time, error) { return r.Get[time.Time]("deleted_at") }); !errors.Is(err, ErrNullValue) {
		t.Errorf("Scan error: %v", err)
	}
}
