package oidc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

// ProtocolOIDC is the identity_protocol code of OpenID Connect connections.
const ProtocolOIDC = "O"

const qConnectionSettings = "oidc_connection_settings"

var providerQueries = map[string]string{
	qConnectionSettings: `
SELECT discovery_url, client_id, client_auth, COALESCE(secret_name, ''), COALESCE(credential_sealed, ''), scopes
  FROM partner_idp_oidc
 WHERE partner_id = ? AND provider_id = ?`,
}

// clientAuthMethods maps oidc_client_auth codes to token endpoint methods.
var clientAuthMethods = map[string]string{"P": AuthSecretPost, "B": AuthSecretBasic, "J": AuthPrivateKey}

// Provider is the OpenID Connect port.IdentityProvider for tenant
// connections. It reads each connection's partner_idp_oidc row and resolves
// its credential from the secret provider (secret_name) or by opening the
// sealed column with Sealer.
type Provider struct {
	DB          port.DatabaseRepository
	Secrets     secret.SecretProvider
	Sealer      *crypto.Sealer
	HTTP        *http.Client  // nil = common.PublicHTTPClient()
	MetadataTTL time.Duration // 0 = social_jwks_cache_ttl

	once    sync.Once
	qs      port.QueryService
	mu      sync.Mutex
	clients map[int64]cachedClient
}

type cachedClient struct {
	fingerprint [32]byte
	client      *Client
}

var _ port.IdentityProvider = (*Provider)(nil)

func (p *Provider) Protocol() string { return ProtocolOIDC }

func (p *Provider) Begin(ctx context.Context, conn port.IdentityConnection, req port.IdentityBegin) (*port.IdentityRedirect, error) {
	c, err := p.client(ctx, conn)
	if err != nil {
		return nil, err
	}
	return c.Begin(ctx, req)
}

func (p *Provider) Complete(ctx context.Context, conn port.IdentityConnection, cb port.IdentityCallback) (*port.IdentityAssertion, error) {
	c, err := p.client(ctx, conn)
	if err != nil {
		return nil, err
	}
	return c.Complete(ctx, cb)
}

// client returns the connection's Client, rebuilt whenever its settings
// change so an edited connection never signs in with stale ones.
func (p *Provider) client(ctx context.Context, conn port.IdentityConnection) (*Client, error) {
	if conn.ID <= 0 || conn.PartnerID <= 0 || conn.Protocol != ProtocolOIDC {
		return nil, fmt.Errorf("%w: connection %d is not an OpenID Connect connection", ErrBadConfiguration, conn.ID)
	}
	s, err := p.settings(ctx, conn)
	if err != nil {
		return nil, err
	}
	fp := sha256.Sum256([]byte(strings.Join([]string{conn.Issuer, conn.SubjectClaim, conn.EmailClaim,
		s.discoveryURL, s.clientID, s.clientAuth, s.secretName, s.sealed, s.scopes}, "\x00")))
	p.mu.Lock()
	if cached, ok := p.clients[conn.ID]; ok && cached.fingerprint == fp {
		p.mu.Unlock()
		return cached.client, nil
	}
	p.mu.Unlock()

	cred, err := p.credential(ctx, s)
	if err != nil {
		return nil, err
	}
	c := &Client{
		Issuer: conn.Issuer, DiscoveryURL: s.discoveryURL, ClientID: s.clientID, Credential: cred,
		Scopes: strings.Fields(s.scopes), SubjectClaim: conn.SubjectClaim, EmailClaim: conn.EmailClaim,
		HTTP: p.HTTP, MetadataTTL: p.MetadataTTL,
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.clients == nil || len(p.clients) >= config.Config().SSOConnectionCacheSize {
		p.clients = map[int64]cachedClient{}
	}
	p.clients[conn.ID] = cachedClient{fingerprint: fp, client: c}
	return c, nil
}

type connectionSettings struct {
	discoveryURL, clientID, clientAuth, secretName, sealed, scopes string
}

func (p *Provider) settings(ctx context.Context, conn port.IdentityConnection) (connectionSettings, error) {
	if p.DB == nil {
		return connectionSettings{}, errors.New("oidc: provider has no database")
	}
	p.once.Do(func() { p.qs = p.DB.GetQueryService(ctx, providerQueries) })
	if p.qs == nil {
		return connectionSettings{}, errors.New("oidc: provider has no query service")
	}
	res, err := p.qs.Query(ctx, qConnectionSettings, conn.PartnerID, conn.ID)
	if err != nil {
		return connectionSettings{}, fmt.Errorf("oidc: settings of connection %d: %w", conn.ID, err)
	}
	if len(res.Rows) != 1 {
		return connectionSettings{}, fmt.Errorf("%w: connection %d has no OpenID Connect settings", ErrBadConfiguration, conn.ID)
	}
	row := res.Rows[0]
	return connectionSettings{
		discoveryURL: common.AsString(row[0]), clientID: common.AsString(row[1]), clientAuth: common.AsString(row[2]),
		secretName: common.AsString(row[3]), sealed: common.AsString(row[4]), scopes: common.AsString(row[5]),
	}, nil
}

func (p *Provider) credential(ctx context.Context, s connectionSettings) (ClientCredential, error) {
	method, ok := clientAuthMethods[s.clientAuth]
	if !ok {
		return ClientCredential{}, fmt.Errorf("%w: client authentication code %q", ErrBadConfiguration, s.clientAuth)
	}
	var raw string
	switch {
	case s.secretName != "" && s.sealed == "":
		if p.Secrets == nil {
			return ClientCredential{}, errors.New("oidc: provider has no secret provider")
		}
		v, err := p.Secrets.GetSecret(ctx, s.secretName)
		if err != nil {
			return ClientCredential{}, fmt.Errorf("oidc: client credential %q: %w", s.secretName, err)
		}
		raw = v
	case s.sealed != "" && s.secretName == "":
		if p.Sealer == nil {
			return ClientCredential{}, errors.New("oidc: provider has no sealer")
		}
		v, err := p.Sealer.Open(s.sealed)
		if err != nil {
			return ClientCredential{}, fmt.Errorf("oidc: open client credential: %w", err)
		}
		raw = v
	default:
		return ClientCredential{}, fmt.Errorf("%w: exactly one of secret name and sealed credential is required", ErrBadConfiguration)
	}
	if method != AuthPrivateKey {
		return ClientCredential{Method: method, Secret: raw}, nil
	}
	key, cert, err := ParseClientKey(raw)
	if err != nil {
		return ClientCredential{}, err
	}
	return ClientCredential{Method: method, Key: key, Certificate: cert}, nil
}
