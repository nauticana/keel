package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/guard"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type APIKeyCacheEntry struct {
	PartnerID int64
	KeyID     int64
	UserID    int64 // 0 for a partner-only key
	Scopes    string
	CachedAt  time.Time
	ExpiresAt time.Time
	// AllowedNets are the networks the key may be used from; empty allows any.
	AllowedNets []netip.Prefix
}

type APIKeyService struct {
	DB           port.DatabaseRepository
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

	// ScopePolicy refuses the scopes of a key to be generated; nil admits any.
	// A rolled key keeps its scopes unchecked.
	ScopePolicy func(scopes string) error

	// CacheTTL bounds how long a validated key stays trusted in memory, and
	// therefore the worst-case lag before an is_active=FALSE revocation takes
	// effect. Defaults to 1 minute when zero.
	CacheTTL time.Duration

	mu    sync.RWMutex
	cache map[string]*APIKeyCacheEntry
	qs    port.QueryService
}

const (
	insertAPIKey      = "insert_api_key"
	insertUserAPIKey  = "insert_user_api_key"
	validateAPIKey    = "validate_api_key"
	updateLastUsed    = "update_last_used"
	rotateAPIKey      = "rotate_api_key"
	countActiveKeys   = "count_active_api_keys"
	restrictAPIKey    = "restrict_api_key"
	apiKeyPartnerLock = "api_key:partner:"
)

var apiKeyQueries = map[string]string{
	insertAPIKey: `
INSERT INTO api_key (id, partner_id, key_name, key_prefix, key_hash, scopes, allowed_cidrs)
VALUES (nextval('api_key_seq'), ?, ?, ?, ?, ?, ?)
RETURNING id`,

	insertUserAPIKey: `
INSERT INTO api_key (id, partner_id, key_name, key_prefix, key_hash, scopes, allowed_cidrs, user_id)
VALUES (nextval('api_key_seq'), ?, ?, ?, ?, ?, ?, ?)
RETURNING id`,

	validateAPIKey: `
SELECT id, partner_id, scopes, expires_at, user_id, allowed_cidrs
  FROM api_key
 WHERE key_hash = ?
   AND is_active = TRUE`,

	updateLastUsed: `
UPDATE api_key SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`,

	rotateAPIKey: `
UPDATE api_key
   SET expires_at       = CURRENT_TIMESTAMP + INTERVAL '24 hours',
       rotated_at       = CURRENT_TIMESTAMP,
       grace_expires_at = CURRENT_TIMESTAMP + INTERVAL '24 hours'
 WHERE id = ? AND partner_id = ? AND is_active = TRUE
RETURNING key_hash, key_name, scopes, user_id, allowed_cidrs`,

	countActiveKeys: `
SELECT COUNT(*) FROM api_key
 WHERE partner_id = ? AND is_active = TRUE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,

	restrictAPIKey: `
UPDATE api_key SET allowed_cidrs = ?
 WHERE id = ? AND partner_id = ? AND is_active = TRUE
RETURNING key_hash`,
}

var apiKeyTxQueries = common.MergeMaps(apiKeyQueries, guard.Queries)

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
	if m.CacheTTL == 0 {
		m.CacheTTL = time.Minute
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

var (
	// ErrInvalidScopes wraps a ScopePolicy refusal.
	ErrInvalidScopes = errors.New("api key scopes refused")
	// ErrAPIKeyLimit refuses a key past api_key_max_per_partner.
	ErrAPIKeyLimit = errors.New("api key limit reached")
)

// InsertKey mints a key for the partner and, when userID is positive, the
// user. allowedCIDRs is a CSV of networks the key may be used from; empty
// allows any address. A partner holding api_key_max_per_partner usable keys
// gets ErrAPIKeyLimit.
func (m *APIKeyService) InsertKey(ctx context.Context, partnerID int64, userID int64, keyName, scopes, allowedCIDRs string) (key string, prefix string, err error) {
	if m.ScopePolicy != nil {
		if err := m.ScopePolicy(scopes); err != nil {
			return "", "", fmt.Errorf("%w: %v", ErrInvalidScopes, err)
		}
	}
	nets, err := common.ParseCIDRList(allowedCIDRs)
	if err != nil {
		return "", "", err
	}
	limit := config.Config().APIKeyMaxPerPartner
	if limit <= 0 {
		return m.insertKey(ctx, m.qs, partnerID, userID, keyName, scopes, common.FormatCIDRList(nets))
	}
	tx, err := m.DB.BeginTx(ctx, apiKeyTxQueries)
	if err != nil {
		return "", "", err
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, data.RollbackDetached(tx))
		}
	}()
	if err := guard.Lock(ctx, tx, apiKeyPartnerLock+strconv.FormatInt(partnerID, 10)); err != nil {
		return "", "", err
	}
	res, err := tx.Query(ctx, countActiveKeys, partnerID)
	if err != nil {
		return "", "", err
	}
	if len(res.Rows) != 1 || len(res.Rows[0]) != 1 {
		return "", "", fmt.Errorf("api key count returned %d rows", len(res.Rows))
	}
	active, ok := common.AsInt64OK(res.Rows[0][0])
	if !ok {
		return "", "", fmt.Errorf("api key count has type %T", res.Rows[0][0])
	}
	if active >= int64(limit) {
		return "", "", ErrAPIKeyLimit
	}
	key, prefix, err = m.insertKey(ctx, tx, partnerID, userID, keyName, scopes, common.FormatCIDRList(nets))
	if err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	committed = true
	return key, prefix, nil
}

// RestrictKey replaces the networks an active key of the partner may be used
// from; empty allows any address. It reports false when no such key exists.
func (m *APIKeyService) RestrictKey(ctx context.Context, keyID, partnerID int64, allowedCIDRs string) (bool, error) {
	nets, err := common.ParseCIDRList(allowedCIDRs)
	if err != nil {
		return false, err
	}
	res, err := m.qs.Query(ctx, restrictAPIKey, common.NullIfEmpty(common.FormatCIDRList(nets)), keyID, partnerID)
	if err != nil || len(res.Rows) == 0 {
		return false, err
	}
	m.InvalidateKey(common.AsString(res.Rows[0][0]))
	return true, nil
}

func (m *APIKeyService) insertKey(ctx context.Context, qs port.QueryService, partnerID int64, userID int64, keyName, scopes, allowedCIDRs string) (string, string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", err
	}
	hexStr := hex.EncodeToString(randomBytes)
	plainKey := m.KeyPrefix + hexStr
	prefix := plainKey[:8]

	hash := sha256.Sum256([]byte(plainKey))
	keyHash := hex.EncodeToString(hash[:])

	var err error
	var res *model.QueryResult
	if userID <= 0 {
		res, err = qs.Query(ctx, insertAPIKey, partnerID, keyName, prefix, keyHash, scopes, common.NullIfEmpty(allowedCIDRs))
	} else {
		res, err = qs.Query(ctx, insertUserAPIKey, partnerID, keyName, prefix, keyHash, scopes, common.NullIfEmpty(allowedCIDRs), userID)
	}
	if err != nil {
		return "", "", err
	}
	if len(res.Rows) == 0 {
		return "", "", fmt.Errorf("api key insert returned no row for partner %d", partnerID)
	}
	return plainKey, prefix, nil
}

// LookupKey resolves a hashed API key to its partner / key id / scopes,
// caching positive matches for CacheTTL. A cache hit is also gated on the row's
// expires_at. Revocation via is_active=FALSE (the validateAPIKey filter) is not
// visible to a cache hit, so it takes effect within CacheTTL, not instantly.
func (m *APIKeyService) LookupKey(ctx context.Context, keyHash string) (*APIKeyCacheEntry, error) {
	m.mu.RLock()
	entry, ok := m.cache[keyHash]
	m.mu.RUnlock()
	now := time.Now()
	if ok && now.Sub(entry.CachedAt) < m.CacheTTL {
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
	if len(row) != 6 {
		return nil, fmt.Errorf("api key lookup returned %d columns", len(row))
	}
	nets, err := common.ParseCIDRList(common.AsString(row[5]))
	if err != nil {
		return nil, fmt.Errorf("api key %d: %w", common.AsInt64(row[0]), err)
	}
	expires, _ := row[3].(time.Time)
	if !expires.IsZero() && now.After(expires) {
		// Persist the negative result by simply not caching — the next
		// lookup will hit the DB again, which on a revoked/expired key
		// returns zero rows immediately.
		return nil, nil
	}
	entry = &APIKeyCacheEntry{
		KeyID:       common.AsInt64(row[0]),
		PartnerID:   common.AsInt64(row[1]),
		Scopes:      common.AsString(row[2]),
		ExpiresAt:   expires,
		CachedAt:    now,
		AllowedNets: nets,
	}
	if uid, ok := common.AsInt64OK(row[4]); ok {
		entry.UserID = uid
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

// TouchLastUsed updates only the key's last_used_at — the key-specific half of
// LogUsage. Quota accounting is QuotaMiddleware's job, keyed on partner_id.
func (m *APIKeyService) TouchLastUsed(ctx context.Context, keyID int64) error {
	_, err := m.qs.Query(ctx, updateLastUsed, keyID)
	return err
}

// RotateKey gives the existing key (keyID, owned by partnerID) a 24h grace
// window via expires_at, then issues a fresh key inheriting its name, scopes,
// and ownership (partner + user_id). The old key keeps working until grace
// expiry so callers can swap without downtime; its cache entry is evicted so
// the new expiry takes effect immediately rather than after CacheTTL.
// It keeps the key's network allow-list and does not count toward
// api_key_max_per_partner. Returns the new plaintext key + prefix (shown once). Zero rows — the key is
// not owned by partnerID or already inactive — returns ("", "", nil).
func (m *APIKeyService) RotateKey(ctx context.Context, keyID int64, partnerID int64) (string, string, error) {
	res, err := m.qs.Query(ctx, rotateAPIKey, keyID, partnerID)
	if err != nil {
		return "", "", err
	}
	if len(res.Rows) == 0 {
		return "", "", nil
	}
	row := res.Rows[0]
	oldHash, _ := row[0].(string)
	keyName, _ := row[1].(string)
	scopes, _ := row[2].(string)
	userID := int64(0)
	if uid, ok := row[3].(int64); ok {
		userID = uid
	}
	m.InvalidateKey(oldHash)
	return m.insertKey(ctx, m.qs, partnerID, userID, keyName, scopes, common.AsString(row[4]))
}
