package cache

import (
	"context"
	"fmt"
	"time"
)

// AdmissionScope is one fixed-window counter charged by an admission decision.
type AdmissionScope struct {
	Key    string
	Limit  int64         // highest count the window may reach
	Cost   int64         // amount charged; below 1 charges 1
	Window time.Duration // fixed-window TTL, set when the counter is created
}

// AdmissionResult reports one decision. When Admitted is false nothing was charged.
type AdmissionResult struct {
	Admitted    bool
	RejectedKey string        // scope that would have exceeded its limit
	RetryAfter  time.Duration // rejecting window's remaining TTL, 0 when unknown
	Counts      []int64       // post-charge counters in scope order; nil when rejected
}

// MultiScopeAdmitter charges several fixed-window counters as one all-or-nothing
// decision. Composing single-key increments cannot: a later scope's rejection
// leaves the earlier ones charged, and compensating still exposes the count to
// concurrent callers, so the wider scope over-admits. Separate from CacheService
// because adding a method there breaks every external implementation, so callers
// type-assert. On Redis Cluster all keys must share a hash tag (`{tenant:42}:rpm`).
type MultiScopeAdmitter interface {
	Admit(ctx context.Context, scopes ...AdmissionScope) (AdmissionResult, error)
}

func (s AdmissionScope) normalized() AdmissionScope {
	if s.Cost < 1 {
		s.Cost = 1
	}
	return s
}

func normalizeAdmissionScopes(scopes []AdmissionScope) ([]AdmissionScope, error) {
	normalized := make([]AdmissionScope, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for i, scope := range scopes {
		if scope.Key == "" {
			return nil, fmt.Errorf("cache: admission scope %d has no key", i)
		}
		if scope.Window <= 0 {
			return nil, fmt.Errorf("cache: admission scope %d has a non-positive window", i)
		}
		if _, ok := seen[scope.Key]; ok {
			return nil, fmt.Errorf("cache: admission scope %d repeats key %q", i, scope.Key)
		}
		seen[scope.Key] = struct{}{}
		normalized[i] = scope.normalized()
	}
	return normalized, nil
}
