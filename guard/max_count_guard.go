package guard

import (
	"context"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
)

// MaxCountGuard refuses when a windowed count reaches max — the cap shape behind
// rate and velocity limits, the mirror of MinCountGuard. reason names the limit
// in the error. Query must return the count in column 0:
//
//	SELECT count(*) FROM <table> WHERE partner_id=$1 AND created_at >= $2 ...
type MaxCountGuard struct {
	queryName string
	max       int64
	window    time.Duration
	reason    string
	Args      GuardArgs
}

func NewMaxCountGuard(queryName, reason string, max int64, window time.Duration) *MaxCountGuard {
	return &MaxCountGuard{
		queryName: queryName,
		max:       max,
		window:    window,
		reason:    reason,
		Args: func(in GuardInput, since time.Time) []any {
			return []any{in.PartnerID, since}
		},
	}
}

func (g *MaxCountGuard) Check(ctx context.Context, qs GuardQuerier, in GuardInput) error {
	res, err := qs.Query(ctx, g.queryName, g.Args(in, in.Now.Add(-g.window))...)
	if err != nil {
		return fmt.Errorf("max-count guard (%s): %w", g.reason, err)
	}
	if len(res.Rows) > 0 && len(res.Rows[0]) > 0 && common.AsInt64(res.Rows[0][0]) >= g.max {
		return fmt.Errorf("%s exceeded: max %d per %s: %w", g.reason, g.max, g.window, ErrGuardRejected)
	}
	return nil
}

var _ TrustGuard = (*MaxCountGuard)(nil)
