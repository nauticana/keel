package model

import (
	"errors"
	"strings"
	"testing"
)

func TestQueryResultIndexes(t *testing.T) {
	qr := &QueryResult{Columns: []string{"id", "name", "amount_minor"}}
	idx, err := qr.Indexes("amount_minor", "id")
	if err != nil || len(idx) != 2 || idx[0] != 2 || idx[1] != 0 {
		t.Fatalf("Indexes = %v, %v", idx, err)
	}
	_, err = qr.Indexes("id", "nope", "gone")
	if !errors.Is(err, ErrColumnNotFound) || !strings.Contains(err.Error(), "nope, gone") {
		t.Fatalf("err = %v", err)
	}
	var nilResult *QueryResult
	if _, err := nilResult.Indexes("id"); !errors.Is(err, ErrColumnNotFound) {
		t.Fatalf("nil result err = %v", err)
	}
}

func TestQueryResultAsMaps(t *testing.T) {
	qr := &QueryResult{Columns: []string{"a", "b"}, Rows: [][]any{{1, "x"}, {2}}}
	maps := qr.AsMaps()
	if len(maps) != 2 || maps[0]["b"] != "x" || len(maps[1]) != 1 {
		t.Fatalf("AsMaps = %v", maps)
	}
	if got := (*QueryResult)(nil).AsMaps(); got == nil || len(got) != 0 {
		t.Fatalf("nil AsMaps = %v", got)
	}
}
