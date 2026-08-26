package pgsql

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// SQLSTATE class 23 integrity-constraint codes. Callers turn them into typed
// service errors (409 / 422) instead of substring-matching the message.
const (
	sqlstateUniqueViolation     = "23505"
	sqlstateForeignKeyViolation = "23503"
)

func IsUniqueViolation(err error) bool     { return hasSQLState(err, sqlstateUniqueViolation) }
func IsForeignKeyViolation(err error) bool { return hasSQLState(err, sqlstateForeignKeyViolation) }

func hasSQLState(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
