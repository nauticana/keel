package guard

import (
	"context"
	"time"

	"github.com/nauticana/keel/port"
)

// GuardArgs builds a guard's positional query args from the request facts and
// the window boundary. Overridable so one guard type serves different columns.
type GuardArgs func(in GuardInput, since time.Time) []any

// GuardQuerier is the data dependency a guard needs — an alias of NamedQuerier
// kept for read-site clarity at guard call sites.
type GuardQuerier = port.QueryService

// GuardInput is the fact set a guard evaluates, populated once at the boundary.
// Now is injected so guards are deterministic in tests.
type GuardInput struct {
	PartnerID int64
	APIKeyID  int64
	DedupKey  string // stable request identity, e.g. partner_id+page_url+eval_type
	ClientIP  string
	Now       time.Time
}

// TrustGuard is one composable admission check run before a write/queue tool
// persists. keel ships the mechanism; each guard is constructed with the
// app-owned named SQL and threshold. Returns nil to pass, a wrapped
// ErrGuardRejected / *DuplicateError to refuse, or a plain error on infra failure.
type TrustGuard interface {
	Check(ctx context.Context, qs GuardQuerier, in GuardInput) error
}
