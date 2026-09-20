// Package connect is keel's concrete OAuth-connect layer: a DB-backed
// CredentialStore over partner_credential + auth_nonce (client.CredentialStore),
// the HTTP handler for the authorize/callback/test flow, and a stale-credential
// refresh sweep. Apps supply only the provider registry (which providers, with
// which scopes/secrets); everything else is inherited.
//
// Credentials scope to a partner and an optional entity (0 = tenant-wide, >0 = a
// specific business). The entity rides the OAuth state across the consent
// redirect and the request context into the store (client.WithEntity), so no
// CredentialStore method signature carries it and existing callers stay at 0.
package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/oauth/client"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
	"golang.org/x/sync/singleflight"
)

const (
	// DefaultEncKeySecret is the keystore key holding the 32-byte AES-256 KEK that
	// seals credentials at rest, used when CredentialStoreDB.EncKeySecret is unset.
	DefaultEncKeySecret = "credential_enc_key"
)

// RefreshResult is what a Refresher returns: a fresh access token, and — for
// providers that rotate — a replacement RefreshToken to persist (empty = keep the
// existing one).
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration // access-token lifetime; 0 = not reported
}

// Refresher mints a fresh token from a stored refresh token for the given
// provider. Apps back it with their provider registry (each provider knows its
// client id/secret/endpoint); nil = treat stored credentials as usable as-is
// (long-lived tokens that don't refresh).
type Refresher func(ctx context.Context, provider, refreshToken string) (RefreshResult, error)

const (
	qUpsertConnection   = "cred_upsert_connection"
	qUpdateStatus       = "cred_update_status"
	qTouchChecked       = "cred_touch_checked"
	qClaim              = "cred_claim"
	qRotateCAS          = "cred_rotate_cas"
	qCompleteCAS        = "cred_complete_cas"
	qMarkErroredCAS     = "cred_mark_errored_cas"
	qCredForRefresh     = "cred_for_refresh"
	qGetCredentials     = "cred_get_credentials"
	qGetAPIEndpoint     = "cred_get_api_endpoint"
	qSetAPIEndpoint     = "cred_set_api_endpoint"
	qListActive         = "cred_list_active"
	qConnectedProviders = "cred_connected_providers"
	qActiveConnection   = "cred_active_connection"
	qShopConnections    = "cred_shop_connections"
)

var credentialQueries = map[string]string{
	// rev bumps on every credential-material change (optimistic concurrency); a
	// reauth also clears any stale lease and stamps last_checked.
	qUpsertConnection: `
INSERT INTO partner_credential
 (id, partner_id, entity_id, provider, connection_type, cred_ref, status, api_endpoint, issued_at, last_checked)
VALUES
 (nextval('partner_credential_seq'), ?, ?, ?, ?, ?, 'A', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (partner_id, entity_id, provider)
DO UPDATE SET cred_ref = EXCLUDED.cred_ref, connection_type = EXCLUDED.connection_type,
 status = 'A', api_endpoint = EXCLUDED.api_endpoint, rev = partner_credential.rev + 1,
 lease_until = NULL, issued_at = CURRENT_TIMESTAMP, last_checked = CURRENT_TIMESTAMP
`,
	// Atomic claim: exactly one worker wins (CAS on the worklist rev + an unheld
	// lease) and gets cred_ref to refresh; losers get no row. The lease makes a
	// crash recoverable after the oauth_connect_lease_seconds config window.
	qClaim: `
UPDATE partner_credential
   SET rev = rev + 1, lease_until = CURRENT_TIMESTAMP + (? * INTERVAL '1 second')
 WHERE partner_id = ? AND entity_id = ? AND provider = ? AND rev = ? AND status = 'A'
   AND (lease_until IS NULL OR lease_until < CURRENT_TIMESTAMP)
RETURNING cred_ref
`,
	// CAS on the claimed rev; each completion clears the lease and stamps last_checked.
	qRotateCAS: `
UPDATE partner_credential
   SET cred_ref = ?, rev = rev + 1, lease_until = NULL, last_checked = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND entity_id = ? AND provider = ? AND rev = ?
RETURNING id
`,
	qCompleteCAS: `
UPDATE partner_credential
   SET rev = rev + 1, lease_until = NULL, last_checked = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND entity_id = ? AND provider = ? AND rev = ?
RETURNING id
`,
	qMarkErroredCAS: `
UPDATE partner_credential
   SET status = 'E', rev = rev + 1, lease_until = NULL, last_checked = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND entity_id = ? AND provider = ? AND rev = ? AND status <> 'E'
RETURNING id
`,
	qUpdateStatus: `
UPDATE partner_credential SET status = ?, rev = rev + 1, last_checked = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND entity_id = ? AND provider = ? AND connection_type = ?
`,
	qTouchChecked: `
UPDATE partner_credential SET last_checked = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND entity_id = ? AND provider = ?
`,
	// Raw sealed cred_ref + rev, read together so an interactive refresh and its
	// CAS write target the same revision.
	qCredForRefresh: `
SELECT cred_ref, rev, status FROM partner_credential
 WHERE partner_id = ? AND entity_id = ? AND provider = ? AND status != 'P'
`,
	qGetCredentials: `
SELECT cred_ref, COALESCE(api_endpoint, '')
  FROM partner_credential
 WHERE partner_id = ? AND entity_id = ? AND provider = ? AND status != 'P'
 ORDER BY last_checked DESC NULLS LAST
 LIMIT 1
`,
	qGetAPIEndpoint: `
SELECT COALESCE(api_endpoint, '')
  FROM partner_credential
 WHERE partner_id = ? AND entity_id = ? AND provider = ? AND status != 'P'
 ORDER BY last_checked DESC NULLS LAST
 LIMIT 1
`,
	qSetAPIEndpoint: `
UPDATE partner_credential SET api_endpoint = ?
 WHERE partner_id = ? AND entity_id = ? AND provider = ?
`,
	qConnectedProviders: `
SELECT DISTINCT provider FROM partner_credential
 WHERE partner_id = ? AND entity_id = ? AND status = 'A'
 ORDER BY provider
`,
	qActiveConnection: `
SELECT connection_type, cred_ref, COALESCE(api_endpoint, ''), rev
  FROM partner_credential
 WHERE partner_id = ? AND entity_id = ? AND provider = ? AND status = 'A'
`,
	// Any status: shop/redact arrives 48h after the uninstall.
	qShopConnections: `
SELECT partner_id, entity_id, provider, connection_type, status, rev
  FROM partner_credential
 WHERE provider = ? AND api_endpoint LIKE ?
 ORDER BY partner_id, entity_id
`,
	// OAuth only (API keys don't refresh); skip currently-leased rows. rev lets the
	// sweep claim/CAS its writes.
	qListActive: `
SELECT partner_id, entity_id, provider, connection_type, rev
  FROM partner_credential
 WHERE status = 'A' AND connection_type = 'O'
   AND (last_checked IS NULL OR last_checked < CURRENT_TIMESTAMP - INTERVAL '30 days')
   AND (lease_until IS NULL OR lease_until < CURRENT_TIMESTAMP)
 ORDER BY last_checked NULLS FIRST
`,
}

// CredentialStoreDB implements client.CredentialStore (and connect.Store) over
// partner_credential + auth_nonce, sealing cred_ref at rest with an AES-256-GCM
// KEK from the secret provider.
type CredentialStoreDB struct {
	DB           port.DatabaseRepository
	Secrets      secret.SecretProvider
	Nonce        *NonceService
	EncKeySecret string                   // keystore key of the 32-byte KEK; default DefaultEncKeySecret
	Refresh      Refresher                // provider-aware refresh; nil = tokens used as-is
	Journal      logger.ApplicationLogger // optional; logs best-effort write failures instead of dropping them

	qs  port.QueryService
	kek []byte

	accessOnce   sync.Once
	access       *cache.LRU[accessKey, cachedAccess]
	refreshing   singleflight.Group
	claimBackoff time.Duration // first ResolveAccess retry delay; 0 = defaultClaimBackoff
}

func (s *CredentialStoreDB) logErr(msg string, err error) {
	if s.Journal != nil {
		s.Journal.Error("connect: " + msg + ": " + err.Error())
	}
}

var (
	_ client.CredentialStore = (*CredentialStoreDB)(nil)
	_ Store                  = (*CredentialStoreDB)(nil)
)

// Init loads the KEK (fail-loud if missing/invalid) and caches the QueryService.
// Call once at wiring time; a missing KEK is a startup error, not a silent
// plaintext fallback.
func (s *CredentialStoreDB) Init(ctx context.Context) error {
	if s.EncKeySecret == "" {
		s.EncKeySecret = DefaultEncKeySecret
	}
	key, err := s.loadKEK(ctx)
	if err != nil {
		return err
	}
	s.kek = key
	s.qs = s.DB.GetQueryService(ctx, credentialQueries)
	if s.Nonce != nil {
		s.Nonce.Init(ctx)
	}
	return nil
}

func (s *CredentialStoreDB) seal(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	return crypto.Seal(s.kek, []byte(v))
}

// open reverses seal: a sealed value that won't open (wrong KEK/tampered) is a
// hard error, never leaked as ciphertext; an unsealed value is legacy plaintext.
func (s *CredentialStoreDB) open(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if plain, ok := crypto.Open(s.kek, stored); ok {
		return string(plain), nil
	}
	if crypto.IsSealed(stored) {
		return "", fmt.Errorf("decrypt credential: sealed value failed to open (wrong key or corrupt)")
	}
	return stored, nil
}

// --- OAuth state (delegates to the nonce store; entity rides in extra) ---

type oauthStatePayload struct {
	PartnerID int64             `json:"partner_id"`
	Provider  string            `json:"provider"`
	Extra     map[string]string `json:"extra,omitempty"`
}

func (s *CredentialStoreDB) CreateOAuthState(ctx context.Context, partnerID int64, provider string, extra map[string]string) (string, error) {
	if s.Nonce == nil {
		return "", fmt.Errorf("connect: nonce store not configured")
	}
	payload, err := json.Marshal(oauthStatePayload{PartnerID: partnerID, Provider: provider, Extra: extra})
	if err != nil {
		return "", err
	}
	return s.Nonce.Create(ctx, "oauth_state", string(payload))
}

func (s *CredentialStoreDB) ConsumeOAuthState(ctx context.Context, state, provider string) (int64, map[string]string, error) {
	if s.Nonce == nil {
		return 0, nil, fmt.Errorf("connect: nonce store not configured")
	}
	raw, ok, err := s.Nonce.Consume(ctx, state, "oauth_state", config.Config().OAuthStateTTLSeconds)
	if err != nil {
		return 0, nil, err
	}
	if !ok {
		return 0, nil, fmt.Errorf("invalid or expired oauth state")
	}
	var p oauthStatePayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return 0, nil, err
	}
	if p.Provider != provider {
		return 0, nil, fmt.Errorf("oauth state provider mismatch")
	}
	return p.PartnerID, p.Extra, nil
}

// --- connection persistence (entity read from ctx, 0 = tenant-wide) ---

func (s *CredentialStoreDB) UpsertConnection(ctx context.Context, partnerID int64, provider, connType, credRef, apiEndpoint string) error {
	enc, err := s.seal(credRef)
	if err != nil {
		return fmt.Errorf("seal credential: %w", err)
	}
	_, err = s.qs.Query(ctx, qUpsertConnection, partnerID, client.EntityFromContext(ctx), provider, connType, enc, apiEndpoint)
	return err
}

func (s *CredentialStoreDB) UpdateConnectionStatus(ctx context.Context, partnerID int64, provider, connType, status string) error {
	_, err := s.qs.Query(ctx, qUpdateStatus, status, partnerID, client.EntityFromContext(ctx), provider, connType)
	return err
}

func (s *CredentialStoreDB) touchLastChecked(ctx context.Context, partnerID int64, provider string) error {
	_, err := s.qs.Query(ctx, qTouchChecked, partnerID, client.EntityFromContext(ctx), provider)
	return err
}

func (s *CredentialStoreDB) GetConnectionCredentials(ctx context.Context, partnerID int64, provider string) (string, string, error) {
	res, err := s.qs.Query(ctx, qGetCredentials, partnerID, client.EntityFromContext(ctx), provider)
	if err != nil {
		return "", "", err
	}
	if len(res.Rows) == 0 {
		return "", "", fmt.Errorf("no connection for partner %d provider %s", partnerID, provider)
	}
	cred, err := s.open(common.AsString(res.Rows[0][0]))
	if err != nil {
		return "", "", err
	}
	return cred, common.AsString(res.Rows[0][1]), nil
}

// RefreshAccessToken (client.CredentialStore) is the interactive Test path and
// always exchanges. An active credential is exchanged under the sweep's lease;
// any other status is outside the sweep, so it CAS-writes on the rev it read. A
// nil Refresher stamps last_checked and returns the stored credential as-is.
func (s *CredentialStoreDB) RefreshAccessToken(ctx context.Context, partnerID int64, provider string) (string, error) {
	key := accessKey{partnerID: partnerID, entityID: client.EntityFromContext(ctx), provider: provider}
	return s.retryLostClaim(ctx, key, func() (string, error) {
		raw, rev, status, ok, err := s.credAndRev(ctx, partnerID, provider)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", fmt.Errorf("no connection for partner %d provider %s", partnerID, provider)
		}
		if s.Refresh != nil && status == statusActive {
			return s.mintAccess(ctx, key, rev)
		}
		cred, err := s.open(raw)
		if err != nil {
			return "", err
		}
		if s.Refresh == nil {
			return cred, s.touchLastChecked(ctx, partnerID, provider)
		}
		return s.exchange(ctx, partnerID, provider, cred, rev)
	})
}

// RefreshDue (connect.Store) is the worker-sweep path. It atomically claims the
// credential at expectRev (a lease makes exactly one replica the owner and makes
// a crash recoverable), then refreshes the claimed cred_ref. refreshed is false
// when another replica/reauthorization already held it — the caller counts that
// as skipped, not done.
func (s *CredentialStoreDB) RefreshDue(ctx context.Context, partnerID int64, provider string, expectRev int) (refreshed bool, err error) {
	raw, claimed, err := s.claim(ctx, partnerID, provider, expectRev)
	if err != nil || !claimed {
		return false, err
	}
	rev := expectRev + 1 // claim bumped rev; CAS the completion on it
	cred, err := s.open(raw)
	if err != nil {
		return false, s.errAlso(err, s.markErroredCAS(ctx, partnerID, provider, rev))
	}
	if _, err := s.exchange(ctx, partnerID, provider, cred, rev); err != nil {
		return false, err
	}
	return true, nil
}

// exchange runs the Refresher and CAS-persists the outcome on rev; last_checked
// and the lease are cleared by every completion path.
func (s *CredentialStoreDB) exchange(ctx context.Context, partnerID int64, provider, refreshToken string, rev int) (string, error) {
	res, err := s.exchangeResult(ctx, partnerID, provider, refreshToken, rev)
	return res.AccessToken, err
}

func (s *CredentialStoreDB) exchangeResult(ctx context.Context, partnerID int64, provider, refreshToken string, rev int) (RefreshResult, error) {
	if s.Refresh == nil {
		return RefreshResult{AccessToken: refreshToken}, s.completeCAS(ctx, partnerID, provider, rev)
	}
	res, err := s.Refresh(ctx, provider, refreshToken)
	if err == nil && res.AccessToken == "" {
		err = fmt.Errorf("provider %s returned an empty access token", provider)
	}
	if err != nil {
		return RefreshResult{}, s.errAlso(err, s.markErroredCAS(ctx, partnerID, provider, rev))
	}
	if res.RefreshToken != "" && res.RefreshToken != refreshToken {
		return res, s.rotateCAS(ctx, partnerID, provider, res.RefreshToken, rev)
	}
	return res, s.completeCAS(ctx, partnerID, provider, rev)
}

// claim atomically leases the credential to this worker if it is still at
// expectRev and unheld; returns the raw sealed cred_ref, or claimed=false.
func (s *CredentialStoreDB) claim(ctx context.Context, partnerID int64, provider string, expectRev int) (string, bool, error) {
	res, err := s.qs.Query(ctx, qClaim, config.Config().OAuthConnectLeaseSeconds, partnerID, client.EntityFromContext(ctx), provider, expectRev)
	if err != nil {
		return "", false, err
	}
	if len(res.Rows) == 0 {
		return "", false, nil
	}
	return common.AsString(res.Rows[0][0]), true, nil
}

// credAndRev reads the raw sealed cred_ref and its rev together.
func (s *CredentialStoreDB) credAndRev(ctx context.Context, partnerID int64, provider string) (cred string, rev int, status string, ok bool, err error) {
	res, err := s.qs.Query(ctx, qCredForRefresh, partnerID, client.EntityFromContext(ctx), provider)
	if err != nil || len(res.Rows) == 0 {
		return "", 0, "", false, err
	}
	row := res.Rows[0]
	return common.AsString(row[0]), int(common.AsInt64(row[1])), common.AsString(row[2]), true, nil
}

// completeCAS clears the lease + stamps last_checked on a no-rotation success. A
// lost CAS (a reauth won) is fine — its write already cleared the lease.
func (s *CredentialStoreDB) completeCAS(ctx context.Context, partnerID int64, provider string, rev int) error {
	_, err := s.qs.Query(ctx, qCompleteCAS, partnerID, client.EntityFromContext(ctx), provider, rev)
	return err
}

// markErroredCAS flips status to 'E' only if rev is unchanged (else a concurrent
// write won and must stand). A DB failure is surfaced, not swallowed.
func (s *CredentialStoreDB) markErroredCAS(ctx context.Context, partnerID int64, provider string, rev int) error {
	_, err := s.qs.Query(ctx, qMarkErroredCAS, partnerID, client.EntityFromContext(ctx), provider, rev)
	return err
}

// rotateCAS seals and persists a replacement refresh token only if rev is
// unchanged; a lost CAS (a newer credential won) is not an error.
func (s *CredentialStoreDB) rotateCAS(ctx context.Context, partnerID int64, provider, newRefresh string, rev int) error {
	enc, err := s.seal(newRefresh)
	if err != nil {
		return fmt.Errorf("seal rotated token: %w", err)
	}
	if _, err := s.qs.Query(ctx, qRotateCAS, enc, partnerID, client.EntityFromContext(ctx), provider, rev); err != nil {
		return fmt.Errorf("persist rotated token: %w", err)
	}
	return nil
}

// errAlso surfaces a bookkeeping-write failure alongside the primary error so a
// stuck-active row can't hide behind a logged-only failure.
func (s *CredentialStoreDB) errAlso(primary, secondary error) error {
	if secondary == nil {
		return primary
	}
	s.logErr("bookkeeping write failed", secondary)
	return errors.Join(primary, secondary)
}

func (s *CredentialStoreDB) GetAPIEndpoint(ctx context.Context, partnerID int64, provider string) (string, error) {
	res, err := s.qs.Query(ctx, qGetAPIEndpoint, partnerID, client.EntityFromContext(ctx), provider)
	if err != nil || len(res.Rows) == 0 {
		return "", err
	}
	return common.AsString(res.Rows[0][0]), nil
}

func (s *CredentialStoreDB) SetAPIEndpoint(ctx context.Context, partnerID int64, provider, endpoint string) error {
	_, err := s.qs.Query(ctx, qSetAPIEndpoint, endpoint, partnerID, client.EntityFromContext(ctx), provider)
	return err
}

func (s *CredentialStoreDB) GetSecret(ctx context.Context, key string) (string, error) {
	return s.Secrets.GetSecret(ctx, key)
}

// ListActiveCredentials returns every stale active OAuth credential (oldest
// first) with its rev — the refresh sweep worklist.
func (s *CredentialStoreDB) ListActiveCredentials(ctx context.Context) ([]ActiveCredential, error) {
	res, err := s.qs.Query(ctx, qListActive)
	if err != nil {
		return nil, err
	}
	out := make([]ActiveCredential, 0, len(res.Rows))
	for _, row := range res.Rows {
		out = append(out, ActiveCredential{
			PartnerID:      common.AsInt64(row[0]),
			EntityID:       common.AsInt64(row[1]),
			Provider:       common.AsString(row[2]),
			ConnectionType: common.AsString(row[3]),
			Rev:            int(common.AsInt64(row[4])),
		})
	}
	return out, nil
}

// ShopConnection is one partner_credential row bound to a Shopify shop.
type ShopConnection struct {
	ActiveCredential
	Status string
}

// ConnectionsByShopDomain lists every connection of the provider to the shop,
// whatever its status. The domain is canonicalized, so it carries no LIKE wildcard.
func (s *CredentialStoreDB) ConnectionsByShopDomain(ctx context.Context, provider, shopDomain string) ([]ShopConnection, error) {
	shop, err := client.CanonicalShopDomain(shopDomain)
	if err != nil {
		return nil, err
	}
	res, err := s.qs.Query(ctx, qShopConnections, provider, "https://"+shop+"/%")
	if err != nil {
		return nil, err
	}
	out := make([]ShopConnection, 0, len(res.Rows))
	for _, row := range res.Rows {
		out = append(out, ShopConnection{
			ActiveCredential: ActiveCredential{
				PartnerID:      common.AsInt64(row[0]),
				EntityID:       common.AsInt64(row[1]),
				Provider:       common.AsString(row[2]),
				ConnectionType: common.AsString(row[3]),
				Rev:            int(common.AsInt64(row[5])),
			},
			Status: common.AsString(row[4]),
		})
	}
	return out, nil
}

// ErrNoActiveConnection means the partner has no status 'A' connection to the provider.
var ErrNoActiveConnection = errors.New("no active connection")

const (
	connectionTypeOAuth = "O"
	statusActive        = "A"
)

// ConnectedProviders lists the providers the partner holds an active connection to.
func (s *CredentialStoreDB) ConnectedProviders(ctx context.Context, partnerID int64) ([]string, error) {
	res, err := s.qs.Query(ctx, qConnectedProviders, partnerID, client.EntityFromContext(ctx))
	if err != nil {
		return nil, err
	}
	providers := make([]string, 0, len(res.Rows))
	for _, row := range res.Rows {
		providers = append(providers, common.AsString(row[0]))
	}
	return providers, nil
}

// ErrRefreshInProgress means another worker held the credential's refresh lease
// for the whole retry window; the caller may retry later.
var ErrRefreshInProgress = errors.New("credential refresh in progress elsewhere")

const (
	accessCacheCapacity  = 10000
	accessExpirySkew     = 30 * time.Second
	claimAttempts        = 5
	defaultClaimBackoff  = 250 * time.Millisecond
	claimBumpsBeforeIdle = 2 // claim, then the completing CAS
)

type accessKey struct {
	partnerID int64
	entityID  int64
	provider  string
}

// cachedAccess is valid only while the row is still at rev: any reauthorization
// or refresh elsewhere moves rev and drops the hit.
type cachedAccess struct {
	token string
	rev   int
}

var errClaimLost = errors.New("claim lost")

func (s *CredentialStoreDB) accessCache() *cache.LRU[accessKey, cachedAccess] {
	s.accessOnce.Do(func() { s.access = cache.NewLRU[accessKey, cachedAccess](accessCacheCapacity, nil) })
	return s.access
}

// ResolveAccess returns a usable token and the api endpoint of the partner's
// active connection. OAuth access tokens are minted under the same lease as the
// refresh sweep — one exchange at a time per credential, fleet-wide — and reused
// in-process for oauth_access_token_cache_ttl. Other connection types return the
// stored credential.
func (s *CredentialStoreDB) ResolveAccess(ctx context.Context, partnerID int64, provider string) (token, apiEndpoint string, err error) {
	key := accessKey{partnerID: partnerID, entityID: client.EntityFromContext(ctx), provider: provider}
	token, err = s.retryLostClaim(ctx, key, func() (string, error) {
		res, err := s.qs.Query(ctx, qActiveConnection, partnerID, key.entityID, provider)
		if err != nil {
			return "", err
		}
		if len(res.Rows) == 0 {
			return "", fmt.Errorf("partner %d provider %s: %w", partnerID, provider, ErrNoActiveConnection)
		}
		row := res.Rows[0]
		apiEndpoint = common.AsString(row[2])
		rev := int(common.AsInt64(row[3]))
		if common.AsString(row[0]) != connectionTypeOAuth || s.Refresh == nil {
			return s.open(common.AsString(row[1]))
		}
		if hit, ok := s.accessCache().Get(key); ok && hit.rev == rev {
			return hit.token, nil
		}
		return s.mintAccess(ctx, key, rev)
	})
	if err != nil {
		return "", "", err
	}
	return token, apiEndpoint, nil
}

// retryLostClaim re-runs attempt, which re-reads the row, while its claim loses
// to another worker's lease or a moved rev.
func (s *CredentialStoreDB) retryLostClaim(ctx context.Context, key accessKey, attempt func() (string, error)) (string, error) {
	backoff := s.claimBackoff
	if backoff <= 0 {
		backoff = defaultClaimBackoff
	}
	for n := 1; ; n++ {
		token, err := attempt()
		if !errors.Is(err, errClaimLost) {
			return token, err
		}
		if n == claimAttempts {
			return "", fmt.Errorf("partner %d provider %s: %w", key.partnerID, key.provider, ErrRefreshInProgress)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
	}
}

// mintAccess claims the credential at rev and exchanges it; concurrent callers
// in this process share one exchange.
func (s *CredentialStoreDB) mintAccess(ctx context.Context, key accessKey, rev int) (string, error) {
	flight := fmt.Sprintf("%d/%d/%s/%d", key.partnerID, key.entityID, key.provider, rev)
	token, err, _ := s.refreshing.Do(flight, func() (any, error) {
		raw, claimed, err := s.claim(ctx, key.partnerID, key.provider, rev)
		if err != nil {
			return "", err
		}
		if !claimed {
			return "", errClaimLost
		}
		claimedRev := rev + 1
		cred, err := s.open(raw)
		if err != nil {
			return "", s.errAlso(err, s.markErroredCAS(ctx, key.partnerID, key.provider, claimedRev))
		}
		minted, err := s.exchangeResult(ctx, key.partnerID, key.provider, cred, claimedRev)
		if err != nil {
			return "", err
		}
		if ttl := accessCacheTTL(minted.ExpiresIn); ttl > 0 {
			s.accessCache().Set(key, cachedAccess{token: minted.AccessToken, rev: rev + claimBumpsBeforeIdle}, ttl)
		}
		return minted.AccessToken, nil
	})
	return token.(string), err
}

func accessCacheTTL(expiresIn time.Duration) time.Duration {
	ttl := config.Config().OAuthAccessTokenCacheTTL
	if expiresIn > 0 && expiresIn-accessExpirySkew < ttl {
		ttl = expiresIn - accessExpirySkew
	}
	return ttl
}

func (s *CredentialStoreDB) loadKEK(ctx context.Context) ([]byte, error) {
	return crypto.LoadKEK(ctx, s.Secrets, s.EncKeySecret)
}
