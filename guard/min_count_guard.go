package guard

import (
	"context"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
)

// MinCountGuard refuses when a windowed count is below min — the floor shape
// (e.g. "at least N prior queries before reviewing"), the mirror of
// MaxCountGuard. reason names the requirement in the error. Query must
// return the count in column 0:
//
//	SELECT count(*) FROM <table> WHERE partner_id=$1 AND created_at >= $2 ...
type MinCountGuard struct {
	queryName string
	min       int64
	window    time.Duration
	reason    string
	Args      GuardArgs
}

func NewMinCountGuard(queryName, reason string, min int64, window time.Duration) *MinCountGuard {
	return &MinCountGuard{
		queryName: queryName,
		min:       min,
		window:    window,
		reason:    reason,
		Args: func(in GuardInput, since time.Time) []any {
			return []any{in.PartnerID, since}
		},
	}
}

func (g *MinCountGuard) Check(ctx context.Context, qs GuardQuerier, in GuardInput) error {
	res, err := qs.Query(ctx, g.queryName, g.Args(in, in.Now.Add(-g.window))...)
	if err != nil {
		return fmt.Errorf("min-count guard (%s): %w", g.reason, err)
	}
	var count int64
	if len(res.Rows) > 0 && len(res.Rows[0]) > 0 {
		count = common.AsInt64(res.Rows[0][0])
	}
	if count < g.min {
		return fmt.Errorf("%s: at least %d required: %w", g.reason, g.min, ErrGuardRejected)
	}
	return nil
}

var _ TrustGuard = (*MinCountGuard)(nil)
