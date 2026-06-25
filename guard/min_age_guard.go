package guard

import (
	"context"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
)

// MinAgeGuard refuses when the acting credential is younger than minAge. Query
// must return the credential's creation timestamp in column 0; a missing value
// is treated as "no usable credential":
//
//	SELECT created_at FROM api_key WHERE partner_id=$1 ... ORDER BY created_at LIMIT 1
type MinAgeGuard struct {
	queryName string
	minAge    time.Duration
	Args      func(in GuardInput) []any
}

func NewMinAgeGuard(queryName string, minAge time.Duration) *MinAgeGuard {
	return &MinAgeGuard{
		queryName: queryName,
		minAge:    minAge,
		Args:      func(in GuardInput) []any { return []any{in.PartnerID} },
	}
}

func (g *MinAgeGuard) Check(ctx context.Context, qs GuardQuerier, in GuardInput) error {
	res, err := qs.Query(ctx, g.queryName, g.Args(in)...)
	if err != nil {
		return fmt.Errorf("min-age guard: %w", err)
	}
	if len(res.Rows) == 0 || len(res.Rows[0]) == 0 || res.Rows[0][0] == nil {
		return fmt.Errorf("account has no usable credential: %w", ErrGuardRejected)
	}
	created, perr := common.ParseDBTimestamp(common.AsString(res.Rows[0][0]))
	if perr != nil || created.IsZero() {
		return fmt.Errorf("could not determine account age: %w", ErrGuardRejected)
	}
	if in.Now.Sub(created) < g.minAge {
		return fmt.Errorf("account too new: must be at least %s old: %w", g.minAge, ErrGuardRejected)
	}
	return nil
}

var _ TrustGuard = (*MinAgeGuard)(nil)
