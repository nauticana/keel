package data

import "database/sql"

// ScanRows collapses the rows.Next / rows.Scan / rows.Err loop into one
// call. scan reads one row and returns the typed value; an error from
// scan or rows.Err aborts. Always closes rows.
//
// For pgx consumers (anything using keel/pgsql), use pgx.CollectRows[T]
// instead — pgx ships the same shape natively.
func ScanRows[T any](rows *sql.Rows, scan func(*sql.Rows) (T, error)) ([]T, error) {
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
