package guard

import (
	"context"
)

// Composable admission guards for write/queue tools. keel ships the mechanism;
// the app supplies each guard's named SQL and threshold. Compose with
// NewGuardChain. Each guard documents the query result shape it expects;
// override Args when the default scoping columns don't fit.

// GuardChain runs guards in order, failing fast on the first refusal and
// returning its error verbatim. An empty chain passes.
type GuardChain struct {
	guards []TrustGuard
}

func NewGuardChain(guards ...TrustGuard) *GuardChain {
	return &GuardChain{guards: guards}
}

func (c *GuardChain) Check(ctx context.Context, qs GuardQuerier, in GuardInput) error {
	for _, g := range c.guards {
		if err := g.Check(ctx, qs, in); err != nil {
			return err
		}
	}
	return nil
}

var _ TrustGuard = (*GuardChain)(nil)
