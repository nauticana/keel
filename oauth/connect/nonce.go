package connect

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

const (
	qNonceInsert  = "nonce_insert"
	qNonceConsume = "nonce_consume"
)

var nonceQueries = map[string]string{
	// Purge day-old nonces on each insert to bound the table.
	qNonceInsert: `
WITH purged AS (DELETE FROM auth_nonce WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 day')
INSERT INTO auth_nonce (nonce, purpose, payload) VALUES (?, ?, ?)
`,
	qNonceConsume: `
DELETE FROM auth_nonce
 WHERE nonce = ? AND purpose = ?
   AND created_at > CURRENT_TIMESTAMP - (? * INTERVAL '1 second')
RETURNING payload
`,
}

// NonceService owns auth_nonce: single-use, expiring tokens for OAuth connect
// state and any other short-lived handoff (e.g. registration JWT).
type NonceService struct {
	DB port.DatabaseRepository
	qs port.QueryService
}

// Init caches the QueryService. Call once at wiring time.
func (s *NonceService) Init(ctx context.Context) {
	s.qs = s.DB.GetQueryService(ctx, nonceQueries)
}

// Create stores payload under a fresh random nonce.
func (s *NonceService) Create(ctx context.Context, purpose, payload string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b)
	if _, err := s.qs.Query(ctx, qNonceInsert, nonce, purpose, payload); err != nil {
		return "", err
	}
	return nonce, nil
}

// Consume deletes the nonce and returns its payload if present, matching
// purpose, and younger than ttlSeconds.
func (s *NonceService) Consume(ctx context.Context, nonce, purpose string, ttlSeconds int) (string, bool, error) {
	res, err := s.qs.Query(ctx, qNonceConsume, nonce, purpose, ttlSeconds)
	if err != nil {
		return "", false, err
	}
	if res == nil || len(res.Rows) == 0 {
		return "", false, nil
	}
	return common.AsString(res.Rows[0][0]), true, nil
}
