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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/oauth/client"
	"github.com/nauticana/keel/secret"
)

const (
	oauthStateTTL = 600 // authorize→callback round-trip window, seconds
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
}

// Refresher mints a fresh token from a stored refresh token for the given
// provider. Apps back it with their provider registry (each provider knows its
// client id/secret/endpoint); nil = treat stored credentials as usable as-is
// (long-lived tokens that don't refresh).
type Refresher func(ctx context.Context, provider, refreshToken string) (RefreshResult, error)

const (
	qUpsertConnection = "cred_upsert_connection"
	qUpdateStatus     = "cred_update_status"
	qTouchChecked     = "cred_touch_checked"
	qClaim            = "cred_claim"
	qRotateCAS        = "cred_rotate_cas"
	qCompleteCAS      = "cred_complete_cas"
	qMarkErroredCAS   = "cred_mark_errored_cas"
	qCredForRefresh   = "cred_for_refresh"
	qGetCredentials   = "cred_get_credentials"
	qGetAPIEndpoint   = "cred_get_api_endpoint"
	qSetAPIEndpoint   = "cred_set_api_endpoint"
	qListActive       = "cred_list_active"
)

// leaseSeconds bounds how long a claimed credential stays exclusive to one worker
// before another may reclaim it (crash recovery).
const leaseSeconds = 300

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
	// crash recoverable after leaseSeconds.
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
SELECT cred_ref, rev FROM partner_credential
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
	DB           data.DatabaseRepository
	Secrets      secret.SecretProvider
	Nonce        *NonceService
	EncKeySecret string                   // keystore key of the 32-byte KEK; default DefaultEncKeySecret
	Refresh      Refresher                // provider-aware refresh; nil = tokens used as-is
	Journal      logger.ApplicationLogger // optional; logs best-effort write failures instead of dropping them

	qs  data.QueryService
	kek []byte
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
	raw, ok, err := s.Nonce.Consume(ctx, state, "oauth_state", oauthStateTTL)
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

// RefreshAccessToken (client.CredentialStore) is the interactive Test path: it
// re-reads cred_ref + rev together (so it can't apply a stale credential to a
// newer revision), exchanges, and CAS-persists any rotation/error on that rev. A
// nil Refresher stamps last_checked and returns the stored credential as-is.
func (s *CredentialStoreDB) RefreshAccessToken(ctx context.Context, partnerID int64, provider string) (string, error) {
	raw, rev, ok, err := s.credAndRev(ctx, partnerID, provider)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("no connection for partner %d provider %s", partnerID, provider)
	}
	cred, err := s.open(raw)
	if err != nil {
		return "", err
	}
	if s.Refresh == nil {
		return cred, s.touchLastChecked(ctx, partnerID, provider)
	}
	return s.exchange(ctx, partnerID, provider, cred, rev)
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
	if s.Refresh == nil {
		return refreshToken, s.completeCAS(ctx, partnerID, provider, rev)
	}
	res, err := s.Refresh(ctx, provider, refreshToken)
	if err == nil && res.AccessToken == "" {
		err = fmt.Errorf("provider %s returned an empty access token", provider)
	}
	if err != nil {
		return "", s.errAlso(err, s.markErroredCAS(ctx, partnerID, provider, rev))
	}
	if res.RefreshToken != "" && res.RefreshToken != refreshToken {
		return res.AccessToken, s.rotateCAS(ctx, partnerID, provider, res.RefreshToken, rev)
	}
	return res.AccessToken, s.completeCAS(ctx, partnerID, provider, rev)
}

// claim atomically leases the credential to this worker if it is still at
// expectRev and unheld; returns the raw sealed cred_ref, or claimed=false.
func (s *CredentialStoreDB) claim(ctx context.Context, partnerID int64, provider string, expectRev int) (string, bool, error) {
	res, err := s.qs.Query(ctx, qClaim, leaseSeconds, partnerID, client.EntityFromContext(ctx), provider, expectRev)
	if err != nil {
		return "", false, err
	}
	if len(res.Rows) == 0 {
		return "", false, nil
	}
	return common.AsString(res.Rows[0][0]), true, nil
}

// credAndRev reads the raw sealed cred_ref and its rev together.
func (s *CredentialStoreDB) credAndRev(ctx context.Context, partnerID int64, provider string) (string, int, bool, error) {
	res, err := s.qs.Query(ctx, qCredForRefresh, partnerID, client.EntityFromContext(ctx), provider)
	if err != nil {
		return "", 0, false, err
	}
	if len(res.Rows) == 0 {
		return "", 0, false, nil
	}
	return common.AsString(res.Rows[0][0]), int(common.AsInt64(res.Rows[0][1])), true, nil
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

// loadKEK fetches the 32-byte AES-256 KEK named by EncKeySecret. Accepts hex
// (canonical) or base64 encoding so either keystore form works.
func (s *CredentialStoreDB) loadKEK(ctx context.Context) ([]byte, error) {
	raw, err := s.Secrets.GetSecret(ctx, s.EncKeySecret)
	if err != nil {
		return nil, fmt.Errorf("fetch credential KEK %q: %w", s.EncKeySecret, err)
	}
	if key, err := crypto.DecodeKEK(raw); err == nil {
		return key, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("credential KEK %q is neither hex nor base64: %w", s.EncKeySecret, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("credential KEK %q must be 32 bytes (got %d)", s.EncKeySecret, len(key))
	}
	return key, nil
}
