package idempotency

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

var (
	ErrKeyReused      = errors.New("idempotency key was used with another request body")
	ErrInFlight       = errors.New("a request with this idempotency key is still running")
	ErrOutcomeUnknown = errors.New("the outcome of the first request with this idempotency key is unknown")
)

const (
	qRequestPrune    = "keel_idempotent_request_prune"
	qRequestClaim    = "keel_idempotent_request_claim"
	qRequestFind     = "keel_idempotent_request_find"
	qRequestComplete = "keel_idempotent_request_complete"
	qRequestUnknown  = "keel_idempotent_request_unknown"
	qRequestRelease  = "keel_idempotent_request_release"
)

// Expiry is judged by the database clock. An expired claim is replaced under a new fence.
var requestQueries = map[string]string{
	qRequestPrune: `
DELETE FROM idempotent_request WHERE request_key IN (
       SELECT request_key FROM idempotent_request WHERE expires_at <= CURRENT_TIMESTAMP LIMIT 100 FOR UPDATE SKIP LOCKED)`,
	qRequestClaim: `
INSERT INTO idempotent_request (request_key, body_digest, state_code, fence, expires_at)
VALUES (?, ?, 'I', ?, CURRENT_TIMESTAMP + CAST(? AS INTEGER) * INTERVAL '1 second')
ON CONFLICT (request_key) DO UPDATE
   SET body_digest = EXCLUDED.body_digest, state_code = 'I', fence = EXCLUDED.fence, response = NULL,
       created_at = CURRENT_TIMESTAMP, expires_at = EXCLUDED.expires_at
 WHERE idempotent_request.expires_at <= CURRENT_TIMESTAMP
RETURNING request_key`,
	qRequestFind: `SELECT body_digest, state_code, response FROM idempotent_request WHERE request_key = ?`,
	qRequestComplete: `
UPDATE idempotent_request SET state_code = 'C', response = ?
 WHERE request_key = ? AND fence = ? AND state_code = 'I' RETURNING request_key`,
	qRequestUnknown: `
UPDATE idempotent_request SET state_code = 'U'
 WHERE request_key = ? AND fence = ? AND state_code = 'I' RETURNING request_key`,
	qRequestRelease: `
DELETE FROM idempotent_request WHERE request_key = ? AND fence = ? AND state_code = 'I' RETURNING request_key`,
}

// RequestStore keeps the first response to an inbound request in idempotent_request for a bounded window.
// Unlike a ledger entry, a request expires and is bound to its body.
type RequestStore struct {
	DB port.DatabaseRepository

	once sync.Once
	qs   port.QueryService
}

// Begin claims key for a request with bodyDigest, returning the fence its outcome must present, or the recorded
// response of an earlier request. Otherwise it fails with ErrKeyReused, ErrInFlight or ErrOutcomeUnknown.
func (s *RequestStore) Begin(ctx context.Context, key, bodyDigest string, window time.Duration) (fence string, response []byte, err error) {
	if len(key) != 64 || len(bodyDigest) != 64 || window < time.Second {
		return "", nil, fmt.Errorf("idempotency: a key digest, a body digest and a window of at least one second are required")
	}
	if fence, err = newFence(); err != nil {
		return "", nil, err
	}
	if _, err = s.run(ctx, qRequestPrune); err != nil {
		return "", nil, err
	}
	rows, err := s.run(ctx, qRequestClaim, key, bodyDigest, fence, int64(window/time.Second))
	if err != nil {
		return "", nil, err
	}
	if len(rows) > 0 {
		return fence, nil, nil
	}
	if rows, err = s.run(ctx, qRequestFind, key); err != nil {
		return "", nil, err
	}
	// Gone since the claim: released or expired, so the client may retry.
	if len(rows) == 0 {
		return "", nil, ErrInFlight
	}
	if common.AsString(rows[0][0]) != bodyDigest {
		return "", nil, ErrKeyReused
	}
	switch state := common.AsString(rows[0][1]); state {
	case stateInFlight:
		return "", nil, ErrInFlight
	case stateUnknown:
		return "", nil, ErrOutcomeUnknown
	case stateCompleted:
		if response, ok := rows[0][2].([]byte); ok {
			return "", response, nil
		}
		return "", nil, fmt.Errorf("idempotency: completed request has response type %T", rows[0][2])
	default:
		return "", nil, fmt.Errorf("idempotency: request has unknown state %q", state)
	}
}

// Complete records the response to replay.
func (s *RequestStore) Complete(ctx context.Context, key, fence string, response []byte) error {
	if response == nil {
		return ErrNilResult
	}
	return s.settle(ctx, qRequestComplete, response, key, fence)
}

// MarkUnknown blocks retries of a request that may have taken effect without a recorded response.
func (s *RequestStore) MarkUnknown(ctx context.Context, key, fence string) error {
	return s.settle(ctx, qRequestUnknown, key, fence)
}

// Release forgets a request that provably did not execute.
func (s *RequestStore) Release(ctx context.Context, key, fence string) error {
	return s.settle(ctx, qRequestRelease, key, fence)
}

// settle lands even when the client is already gone.
func (s *RequestStore) settle(ctx context.Context, name string, args ...any) error {
	rows, err := s.run(context.WithoutCancel(ctx), name, args...)
	if err == nil && len(rows) == 0 {
		err = ErrInvalidTransition
	}
	return err
}

func (s *RequestStore) run(ctx context.Context, name string, args ...any) ([][]any, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("idempotency: database is required")
	}
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, requestQueries) })
	res, err := s.qs.Query(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	return res.Rows, nil
}
