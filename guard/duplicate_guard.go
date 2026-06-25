package guard

import (
	"context"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
)

// DuplicateGuard refuses a write when an equivalent request (same DedupKey) is
// in flight or was satisfied inside window, returning *port.DuplicateError with
// the existing id. Query must return that id in column 0, or no rows:
//
//	SELECT id FROM <queue> WHERE partner_id=$1 AND dedup_key=$2 AND created_at >= $3 ... LIMIT 1
type DuplicateGuard struct {
	queryName string
	window    time.Duration
	Args      GuardArgs
}

func NewDuplicateGuard(queryName string, window time.Duration) *DuplicateGuard {
	return &DuplicateGuard{
		queryName: queryName,
		window:    window,
		Args: func(in GuardInput, since time.Time) []any {
			return []any{in.PartnerID, in.DedupKey, since}
		},
	}
}

func (g *DuplicateGuard) Check(ctx context.Context, qs GuardQuerier, in GuardInput) error {
	res, err := qs.Query(ctx, g.queryName, g.Args(in, in.Now.Add(-g.window))...)
	if err != nil {
		return fmt.Errorf("duplicate guard: %w", err)
	}
	if len(res.Rows) > 0 && len(res.Rows[0]) > 0 {
		return &DuplicateError{ExistingID: common.AsInt64(res.Rows[0][0])}
	}
	return nil
}

var _ TrustGuard = (*DuplicateGuard)(nil)
