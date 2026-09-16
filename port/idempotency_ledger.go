package port

import (
	"context"

	"github.com/nauticana/keel/model"
)

// IdempotencyLedger records mutating operations by key so a replay returns the prior result, a concurrent
// attempt sees the key in flight, and an ambiguous outcome blocks retries until reconciled.
//
// A claim carries a fence. With a lease configured, an in-flight claim that has not been renewed within the
// lease may be taken over under a new fence; the previous holder's ledger writes then fail. The fence protects
// the ledger only: a taken-over worker that is merely slow still finishes its external call. A caller that
// enables takeover must make the side effect idempotent under the stable ledger key, arrange for the target to
// reject superseded fences, or leave the lease at zero and reconcile stuck keys explicitly.
type IdempotencyLedger interface {
	// Begin claims a new key, or a lapsed in-flight key, returning LedgerNew with a Fence; otherwise it returns
	// the existing entry without one. Unknown keys are never taken over.
	Begin(ctx context.Context, key string) (model.LedgerEntry, error)
	// Renew extends the holder's lease on an in-flight key so healthy long-running work is not taken over.
	Renew(ctx context.Context, key, fence string) error
	// Complete resolves an in-flight or unknown key as executed; idempotent for the same non-nil result.
	Complete(ctx context.Context, key, fence string, result []byte) error
	// Release forgets an in-flight or unknown key whose operation provably did not execute.
	Release(ctx context.Context, key, fence string) error
	MarkUnknown(ctx context.Context, key, fence string) error
}
