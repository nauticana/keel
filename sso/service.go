// Package sso signs a partner's people in through the partner's own identity
// provider. It resolves the partner from a domain the partner holds by
// identity-grade evidence, runs the connection's protocol through a
// port.IdentityProvider, checks the asserted identity against that partner,
// links or creates the account, applies the role mapping and returns a
// session bound to the partner. It also configures, tests, activates and
// disables connections.
package sso

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/connect"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

const pendingPurpose = "sso_signin"

// Connection statuses (identity_provider_status).
const (
	StatusDraft    = "D"
	StatusActive   = "A"
	StatusDisabled = "X"
)

// Service is the tenant sign-in service. Providers maps an identity_protocol
// code to its implementation; Users must implement user.TenantAccountCreator
// for accounts to be created or joined on first sign-in.
type Service struct {
	DB        port.DatabaseRepository
	Users     user.UserService
	Domains   *domain.Service
	Providers map[string]port.IdentityProvider
	Nonces    *connect.NonceService
	// Sealer seals partner-supplied client credentials at Configure.
	Sealer *crypto.Sealer
	// OperatorClients are the operator's own app registrations a partner may
	// choose instead of supplying a credential, keyed by preset name.
	OperatorClients map[string]OperatorClient

	once sync.Once
	qs   port.QueryService
}

// Outcome is a completed callback: a session for a sign-in, or the partner
// and connection of a passed test.
type Outcome struct {
	Session      *model.UserSession
	Test         bool
	PartnerID    int64
	ConnectionID int64
}

// connection is a partner_identity_provider row.
type connection struct {
	port.IdentityConnection
	Status string
	Tested bool
}

// pendingSignIn is stored server-side under the browser's cookie key.
type pendingSignIn struct {
	ConnectionID int64  `json:"c"`
	PartnerID    int64  `json:"p"`
	Pending      string `json:"x"`
	TesterID     int    `json:"u,omitempty"`
}

// Start begins a sign-in for email. It returns the identity provider URL and
// the key the caller binds to the browser, normally in an HttpOnly cookie.
func (s *Service) Start(ctx context.Context, email, callbackURL string) (string, string, error) {
	partnerID, err := s.holder(ctx, domain.DomainFromEmail(normalizeEmail(email)))
	if errors.Is(err, domain.ErrNotHeld) {
		return "", "", ErrUnavailable
	}
	if err != nil {
		return "", "", err
	}
	conn, err := s.activeConnection(ctx, partnerID)
	if err != nil {
		return "", "", err
	}
	return s.begin(ctx, conn, normalizeEmail(email), callbackURL, nil, 0)
}

// Complete finishes the sign-in or test that key started. A sign-in returns a
// session bound to the connection's partner with sign-in method T; it has not
// been through keel's second factor, which the tenant's IdP replaces.
func (s *Service) Complete(ctx context.Context, key, callbackURL string, params url.Values) (*Outcome, error) {
	if s.Nonces == nil || key == "" {
		return nil, ErrSignInFailed
	}
	payload, ok, err := s.Nonces.Consume(ctx, key, pendingPurpose, config.Config().OAuthStateTTLSeconds)
	if err != nil {
		return nil, err
	}
	var p pendingSignIn
	if !ok || json.Unmarshal([]byte(payload), &p) != nil || p.PartnerID <= 0 || p.ConnectionID <= 0 {
		return nil, ErrSignInFailed
	}
	conn, err := s.connection(ctx, p.PartnerID, p.ConnectionID)
	if errors.Is(err, ErrConnectionNotFound) {
		return nil, ErrSignInFailed
	}
	if err != nil {
		return nil, err
	}
	if conn.Status == StatusDisabled || (p.TesterID == 0 && conn.Status != StatusActive) {
		return nil, ErrSignInFailed
	}
	provider, err := s.provider(conn.Protocol)
	if err != nil {
		return nil, err
	}
	a, err := provider.Complete(ctx, conn.IdentityConnection, port.IdentityCallback{RedirectURI: callbackURL, Params: params, Pending: p.Pending})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignInFailed, err)
	}
	if a.Issuer != conn.Issuer || a.Subject == "" {
		return nil, ErrSignInFailed
	}
	if conn.RequireMFA && !hasMFA(a.AuthMethods) {
		return nil, ErrMFARequired
	}
	if p.TesterID > 0 {
		if err := s.completeTest(ctx, conn, p.TesterID, a); err != nil {
			return nil, err
		}
		return &Outcome{Test: true, PartnerID: conn.PartnerID, ConnectionID: conn.ID}, nil
	}
	if err := s.checkIdentityDomain(ctx, conn, a); err != nil {
		return nil, err
	}
	session, err := s.signIn(ctx, conn, a)
	if err != nil {
		return nil, err
	}
	return &Outcome{Session: session, PartnerID: conn.PartnerID, ConnectionID: conn.ID}, nil
}

func (s *Service) begin(ctx context.Context, conn *connection, loginHint, callbackURL string, scopes []string, testerID int) (string, string, error) {
	if s.Nonces == nil {
		return "", "", errors.New("sso: no nonce service")
	}
	provider, err := s.provider(conn.Protocol)
	if err != nil {
		return "", "", err
	}
	state, err := randomKey()
	if err != nil {
		return "", "", err
	}
	r, err := provider.Begin(ctx, conn.IdentityConnection, port.IdentityBegin{State: state, RedirectURI: callbackURL, LoginHint: loginHint, Scopes: scopes})
	if err != nil {
		return "", "", err
	}
	payload, err := json.Marshal(pendingSignIn{ConnectionID: conn.ID, PartnerID: conn.PartnerID, Pending: r.Pending, TesterID: testerID})
	if err != nil {
		return "", "", err
	}
	key, err := s.Nonces.Create(ctx, pendingPurpose, string(payload))
	if err != nil {
		return "", "", err
	}
	return r.URL, key, nil
}

// checkIdentityDomain admits only an email, and for Google a hosted domain,
// inside a domain the connection's partner holds by identity-grade evidence.
// An issuer may vouch only for its own organization's addresses.
func (s *Service) checkIdentityDomain(ctx context.Context, conn *connection, a *port.IdentityAssertion) error {
	names := []string{domain.DomainFromEmail(normalizeEmail(a.Email))}
	if a.Issuer == googleIssuer {
		names = append(names, a.HostedDomain)
	}
	for _, name := range names {
		holder, err := s.holder(ctx, name)
		if errors.Is(err, domain.ErrNotHeld) || (err == nil && holder != conn.PartnerID) {
			return ErrEmailNotAllowed
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) holder(ctx context.Context, name string) (int64, error) {
	return holderOf(ctx, s.Domains, name)
}

// holderOf returns the partner holding name, or the nearest parent domain,
// by identity-grade evidence.
func holderOf(ctx context.Context, domains *domain.Service, name string) (int64, error) {
	name, ok := domain.DomainName(name)
	if !ok || domains == nil {
		return 0, domain.ErrNotHeld
	}
	for {
		id, err := domains.IdentityHolder(ctx, name)
		if !errors.Is(err, domain.ErrNotHeld) {
			return id, err
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 || !strings.Contains(name[dot+1:], ".") {
			return 0, domain.ErrNotHeld
		}
		name = name[dot+1:]
	}
}

func (s *Service) activeConnection(ctx context.Context, partnerID int64) (*connection, error) {
	conn, err := activeConnectionOn(ctx, s.query(ctx), partnerID)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, ErrUnavailable
	}
	return conn, nil
}

// activeConnectionOn returns the partner's active connection, or nil.
func activeConnectionOn(ctx context.Context, qs port.QueryService, partnerID int64) (*connection, error) {
	res, err := qs.Query(ctx, qActiveConnection, partnerID)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) != 1 {
		return nil, nil
	}
	return connectionFromRow(res.Rows[0]), nil
}

func (s *Service) connection(ctx context.Context, partnerID, id int64) (*connection, error) {
	if partnerID <= 0 || id <= 0 {
		return nil, ErrConnectionNotFound
	}
	res, err := s.query(ctx).Query(ctx, qConnection, partnerID, id)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) != 1 {
		return nil, ErrConnectionNotFound
	}
	return connectionFromRow(res.Rows[0]), nil
}

func connectionFromRow(row []any) *connection {
	return &connection{
		IdentityConnection: port.IdentityConnection{
			ID: common.AsInt64(row[0]), PartnerID: common.AsInt64(row[1]), Protocol: common.AsString(row[2]),
			Issuer: common.AsString(row[3]), SubjectClaim: common.AsString(row[4]), EmailClaim: common.AsString(row[5]),
			RequireMFA: common.AsBool(row[6]),
		},
		Status: common.AsString(row[7]),
		Tested: common.AsBool(row[8]),
	}
}

func (s *Service) provider(protocol string) (port.IdentityProvider, error) {
	p, ok := s.Providers[protocol]
	if !ok || p == nil {
		return nil, fmt.Errorf("sso: no identity provider for protocol %q", protocol)
	}
	return p, nil
}

func (s *Service) query(ctx context.Context) port.QueryService {
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, allQueries) })
	return s.qs
}

// hasMFA reads RFC 8176 authentication method references.
func hasMFA(methods []string) bool {
	for _, m := range methods {
		if m == "mfa" {
			return true
		}
	}
	return false
}

func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func randomKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
