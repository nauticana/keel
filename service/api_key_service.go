package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

type APIKeyCacheEntry struct {
	PartnerID int64
	KeyID     int64
	Scopes    string
	CachedAt  time.Time
	ExpiresAt time.Time
}

type APIKeyService struct {
	DB           data.DatabaseRepository
	QuotaService port.QuotaService
	Journal      logger.ApplicationLogger

	// KeyPrefix is the user-visible prefix on issued keys. Required —
	// empty triggers a panic at Init so consumers must opt in explicitly.
	KeyPrefix string
	// QuotaResource is the resource id passed to QuotaService.LogUsage.
	// Defaults to "API_CALLS" when empty.
	QuotaResource string
	// QuotaCaption is the caption passed to QuotaService.LogUsage.
	// Defaults to "public-api" when empty.
	QuotaCaption string

	mu    sync.RWMutex
	cache map[string]*APIKeyCacheEntry
	qs    data.QueryService
}

const (
	insertAPIKey   = "insert_api_key"
	validateAPIKey = "validate_api_key"
	updateLastUsed = "update_last_used"
)

var apiKeyQueries = map[string]string{
	insertAPIKey: `
INSERT INTO api_key (id, partner_id, key_name, key_prefix, key_hash, scopes)
VALUES (nextval('api_key_seq'), ?, ?, ?, ?, ?)`,

	validateAPIKey: `
SELECT id, partner_id, scopes, expires_at
  FROM api_key
 WHERE key_hash = ?
   AND is_active = TRUE`,

	updateLastUsed: `
UPDATE api_key SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`,
}

func (m *APIKeyService) Init(ctx context.Context) {
	if m.KeyPrefix == "" {
		panic("APIKeyService.KeyPrefix is required (e.g. \"dax_\", \"rap_\")")
	}
	if m.QuotaResource == "" {
		m.QuotaResource = "API_CALLS"
	}
	if m.QuotaCaption == "" {
		m.QuotaCaption = "public-api"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cache == nil {
		m.cache = make(map[string]*APIKeyCacheEntry)
	}
	if m.qs == nil {
		m.qs = m.DB.GetQueryService(ctx, apiKeyQueries)
	}
}

func (m *APIKeyService) InsertKey(ctx context.Context, partnerID int64, keyName string, scopes string) (string, string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", err
	}
	hexStr := hex.EncodeToString(randomBytes)
	plainKey := m.KeyPrefix + hexStr
	prefix := plainKey[:8]

	hash := sha256.Sum256([]byte(plainKey))
	keyHash := hex.EncodeToString(hash[:])

	res, err := m.qs.Query(ctx, insertAPIKey, partnerID, keyName, prefix, keyHash, scopes)
	if err != nil || len(res.Rows) == 0 {
		return "", "", err
	}
	return plainKey, prefix, nil
}

// LookupKey resolves a hashed API key to its partner / key id / scopes,
// caching positive matches for up to 5 minutes. A cache hit is also gated
// on the row's expires_at — keys past their declared expiry are rejected
// even when still in the cache so a freshly-revoked or end-of-life key
// stops working immediately rather than after the TTL elapses. Cache
// entries with a zero ExpiresAt indicate "no expiry set" and pass.
func (m *APIKeyService) LookupKey(ctx context.Context, keyHash string) (*APIKeyCacheEntry, error) {
	m.mu.RLock()
	entry, ok := m.cache[keyHash]
	m.mu.RUnlock()
	now := time.Now()
	if ok && now.Sub(entry.CachedAt) < 5*time.Minute {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			// Expired key — drop from cache and refuse without a DB hit.
			m.InvalidateKey(keyHash)
			return nil, nil
		}
		return entry, nil
	}

	res, err := m.qs.Query(ctx, validateAPIKey, keyHash)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, nil
	}

	row := res.Rows[0]
	expires, _ := row[3].(time.Time)
	if !expires.IsZero() && now.After(expires) {
		// Persist the negative result by simply not caching — the next
		// lookup will hit the DB again, which on a revoked/expired key
		// returns zero rows immediately.
		return nil, nil
	}
	entry = &APIKeyCacheEntry{
		KeyID:     row[0].(int64),
		PartnerID: row[1].(int64),
		Scopes:    row[2].(string),
		ExpiresAt: expires,
		CachedAt:  now,
	}
	m.mu.Lock()
	m.cache[keyHash] = entry
	m.mu.Unlock()

	return entry, nil
}

func (m *APIKeyService) InvalidateKey(keyHash string) {
	m.mu.Lock()
	delete(m.cache, keyHash)
	m.mu.Unlock()
}

func (m *APIKeyService) LogUsage(ctx context.Context, partnerID int64, keyID int64) error {
	err := m.QuotaService.LogUsage(ctx, partnerID, m.QuotaResource, 1, m.QuotaCaption)
	if err != nil {
		return err
	}
	_, err = m.qs.Query(ctx, updateLastUsed, keyID)
	return err
}
