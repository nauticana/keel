package model

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRowInto(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	qr := &QueryResult{Columns: []string{"id", "name", "note", "active", "at", "count"},
		Rows: [][]any{{int32(7), "a", nil, true, at, int64(3)}}}
	row, _ := qr.Row(0)
	var (
		id     int64
		name   string
		note   *string
		active bool
		when   time.Time
		count  int
	)
	if err := row.Into(&id, &name, &note, &active, &when, &count); err != nil {
		t.Fatal(err)
	}
	if id != 7 || name != "a" || note != nil || !active || !when.Equal(at) || count != 3 {
		t.Fatalf("got %d %q %v %v %v %d", id, name, note, active, when, count)
	}
}

func TestRowIntoNamesTheFailingColumn(t *testing.T) {
	qr := &QueryResult{Columns: []string{"id", "note"}, Rows: [][]any{{int64(1), nil}}}
	row, _ := qr.Row(0)
	var id int64
	var note string
	if err := row.Into(&id, &note); !errors.Is(err, ErrNullValue) || !strings.Contains(err.Error(), "column note") {
		t.Fatalf("NULL into string: %v", err)
	}
	if err := row.Into(&id, &note, &id); !errors.Is(err, ErrColumnNotFound) {
		t.Fatalf("too many targets: %v", err)
	}
	if err := row.Into((*int64)(nil)); !errors.Is(err, ErrCoercion) {
		t.Fatalf("nil target: %v", err)
	}
	if err := row.Into(nil); !errors.Is(err, ErrCoercion) {
		t.Fatalf("untyped nil target: %v", err)
	}
	var unsupported struct{}
	if err := row.Into(&unsupported); !errors.Is(err, ErrCoercion) {
		t.Fatalf("unsupported target: %v", err)
	}
}
