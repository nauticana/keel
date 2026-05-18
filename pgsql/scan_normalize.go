package pgsql

import (
	"github.com/jackc/pgx/v5/pgtype"
)

// normalizeValue converts the pgx-specific wrapper types that arrive
// from a Scan-into-*any into the primitive Go types keel's
// `common.As*` helpers (AsFloat64, AsTime, ...) actually recognize.
//
// Why this exists: pgx's default codec decodes PG `NUMERIC` to
// pgtype.Numeric (a struct wrapping a *big.Int + Exp). Callers that
// pass the scanned value through `common.AsFloat64` would hit the
// default branch and receive the `-1` sentinel — silently corrupting
// every NUMERIC column (money, coordinates, rates). Same story for
// pgtype.Date / Timestamp / Timestamptz against `common.AsTime`. By
// converting at the scan boundary we keep the keel/common helpers'
// type switches tight (they stay free of pgx dependencies) and every
// downstream service automatically gets correct values.
//
// A NULL column (Valid=false on the typed wrapper) becomes Go nil so
// existing nil checks (`if v == nil`) keep working unchanged.
//
// Loss-of-precision note: NUMERIC values with more than ~15 significant
// digits round when converted to float64. If a consumer ever stores
// arbitrary-precision values in NUMERIC and expects exact reads,
// they should call pgx directly (or via TableService.Get) and skip
// the QueryService path.
func normalizeValue(v any) any {
	switch n := v.(type) {
	case pgtype.Numeric:
		if !n.Valid {
			return nil
		}
		f, err := n.Float64Value()
		if err != nil || !f.Valid {
			return nil
		}
		return f.Float64
	case pgtype.Date:
		if !n.Valid {
			return nil
		}
		return n.Time
	case pgtype.Timestamp:
		if !n.Valid {
			return nil
		}
		return n.Time
	case pgtype.Timestamptz:
		if !n.Valid {
			return nil
		}
		return n.Time
	}
	return v
}
