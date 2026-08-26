package pgsql

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSQLStateHelpers(t *testing.T) {
	unique := fmt.Errorf("insert: %w", &pgconn.PgError{Code: "23505"})
	fk := &pgconn.PgError{Code: "23503"}
	if !IsUniqueViolation(unique) || IsForeignKeyViolation(unique) {
		t.Error("23505 must be unique, not FK")
	}
	if !IsForeignKeyViolation(fk) || IsUniqueViolation(fk) {
		t.Error("23503 must be FK, not unique")
	}
	if IsUniqueViolation(nil) || IsUniqueViolation(errors.New("duplicate key")) {
		t.Error("nil / plain errors must not match")
	}
}
