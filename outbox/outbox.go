// Package outbox implements a transactional outbox: events are captured in the
// same database transaction as a domain write (EnqueueTx), then drained by a
// lease-based worker (see Worker) for reliable at-least-once delivery. This lets
// a service commit a state change and its side-effect intent atomically, with no
// dual-write race — the side effect runs later, retried until it succeeds.
package outbox

import (
	"context"

	"github.com/nauticana/keel/data"
)

// Status codes for outbox_event.status.
const (
	StatusPending = "P" // ready to dispatch once available_at passes
	StatusActive  = "A" // claimed by a worker; lease_until guards a crashed claim
	StatusDone    = "D" // dispatched
	StatusFailed  = "F" // dead-lettered after MaxAttempts
)

// Event is one row to enqueue. The id, status, attempt count, and timestamps are
// assigned by EnqueueTx; callers supply only the routing + payload fields.
type Event struct {
	PartnerID     int64  // 0 → stored NULL (event is not partner-scoped)
	AggregateType string // the kind of entity the event is about, e.g. "business"
	AggregateID   string // the entity's id (string for flexibility across key types)
	EventType     string // e.g. "profile.updated"
	Payload       string // JSON; "" → stored NULL
}

const qInsert = "keel_outbox_insert"

// WriteQueries returns the named query a caller merges into its BeginTx query map
// so EnqueueTx can run inside the caller's transaction.
func WriteQueries() map[string]string {
	return map[string]string{
		qInsert: `INSERT INTO outbox_event
			(id, partner_id, aggregate_type, aggregate_id, event_type, payload, status, attempts, available_at, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, 'P', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
	}
}

// EnqueueTx inserts one event using the caller's transaction — which must have
// merged WriteQueries() into its query map. The insert commits or rolls back
// atomically with the surrounding domain write: the outbox guarantee.
func EnqueueTx(ctx context.Context, tx data.TxQueryService, e Event) error {
	_, err := tx.Query(ctx, qInsert, tx.GenID(), nullIfZero(e.PartnerID),
		e.AggregateType, e.AggregateID, e.EventType, nullIfEmpty(e.Payload))
	return err
}

func nullIfZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
