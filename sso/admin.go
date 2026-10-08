package sso

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/port"
)

// domainProof is the grant a test sign-in asks for so the same round trip
// records identity-grade domain evidence.
type domainProof struct {
	method string
	scopes []string
}

// domainProofFor returns the proof an OpenID Connect issuer's test sign-in
// can carry, if any.
func domainProofFor(protocol, issuer string) (domainProof, bool) {
	switch {
	case protocol != ProtocolOIDC:
		return domainProof{}, false
	case isEntra(issuer):
		return domainProof{domain.MethodMicrosoftEntra, []string{
			"https://graph.microsoft.com/Domain.Read.All", "https://graph.microsoft.com/Directory.Read.All"}}, true
	case issuer == googleIssuer:
		return domainProof{domain.MethodGoogleWorkspace, []string{
			"https://www.googleapis.com/auth/admin.directory.domain.readonly"}}, true
	}
	return domainProof{}, false
}

// Configure creates a draft connection, or changes the partner's connection
// cfg.ID. An active connection may only rotate its credential and edit its
// claims and caption; changing its issuer or client needs a disable first.
func (s *Service) Configure(ctx context.Context, partnerID int64, userID int, cfg Configuration) (int64, error) {
	if partnerID <= 0 || userID <= 0 {
		return 0, ErrConnectionNotFound
	}
	set, err := s.validate(cfg)
	if err != nil {
		return 0, err
	}
	keepTest := false
	if cfg.ID > 0 {
		current, err := s.connection(ctx, partnerID, cfg.ID)
		if err != nil {
			return 0, err
		}
		if current.Protocol != set.protocol {
			return 0, fmt.Errorf("%w: the protocol of a connection cannot change", ErrInvalidConfiguration)
		}
		sameClient := true
		if set.protocol == ProtocolOIDC {
			res, err := s.query(ctx).Query(ctx, qConnectionClient, partnerID, cfg.ID)
			if err != nil {
				return 0, err
			}
			sameClient = len(res.Rows) == 1 && common.AsString(res.Rows[0][0]) == set.clientID
		}
		keepTest = sameClient && current.Issuer == set.issuer
		if current.Status == StatusActive && !keepTest {
			return 0, ErrConnectionActive
		}
	}
	tx, err := s.DB.BeginTx(ctx, allQueries)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	id := cfg.ID
	secretName, sealed := nullable(set.secretName), nullable(set.sealed)
	if id == 0 {
		res, err := tx.Query(ctx, qInsertConnection, partnerID, set.caption, set.protocol, set.issuer, set.subjectClaim, set.emailClaim, set.requireMFA, userID)
		if err != nil {
			return 0, fmt.Errorf("sso: insert connection: %w", err)
		}
		if len(res.Rows) != 1 {
			return 0, errors.New("sso: insert connection returned no id")
		}
		id = common.AsInt64(res.Rows[0][0])
		if err := insertSettings(ctx, tx, partnerID, id, set, secretName, sealed); err != nil {
			return 0, err
		}
	} else {
		if _, err := tx.Query(ctx, qUpdateConnection, set.caption, set.issuer, set.subjectClaim, set.emailClaim, set.requireMFA, keepTest, keepTest, partnerID, id); err != nil {
			return 0, fmt.Errorf("sso: update connection: %w", err)
		}
		if err := updateSettings(ctx, tx, partnerID, id, set, secretName, sealed); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("sso: commit configuration: %w", err)
	}
	committed = true
	return id, nil
}

func insertSettings(ctx context.Context, tx port.QueryService, partnerID, id int64, set *settings, secretName, sealed any) error {
	var err error
	if set.protocol == ProtocolSAML {
		_, err = tx.Query(ctx, qInsertSAML, partnerID, id, set.metadata)
	} else {
		_, err = tx.Query(ctx, qInsertOIDC, partnerID, id, set.discoveryURL, set.clientID, set.clientAuth, secretName, sealed, set.scopes)
	}
	if err != nil {
		return fmt.Errorf("sso: insert settings: %w", err)
	}
	return nil
}

func updateSettings(ctx context.Context, tx port.QueryService, partnerID, id int64, set *settings, secretName, sealed any) error {
	var err error
	if set.protocol == ProtocolSAML {
		_, err = tx.Query(ctx, qUpdateSAML, set.metadata, partnerID, id)
	} else {
		_, err = tx.Query(ctx, qUpdateOIDC, set.discoveryURL, set.clientID, set.clientAuth, secretName, sealed, set.scopes, partnerID, id)
	}
	if err != nil {
		return fmt.Errorf("sso: update settings: %w", err)
	}
	return nil
}

// BeginTest starts a test sign-in of a draft or active connection by the
// administrator userID. The identity provider must assert the
// administrator's own email; for Entra ID and Google the same round trip asks
// for the grant that proves the email's domain.
func (s *Service) BeginTest(ctx context.Context, partnerID int64, userID int, connectionID int64, callbackURL string) (string, string, error) {
	conn, err := s.connection(ctx, partnerID, connectionID)
	if err != nil {
		return "", "", err
	}
	if conn.Status == StatusDisabled {
		return "", "", ErrConnectionNotFound
	}
	tester, err := s.Users.GetUserById(userID)
	if err != nil {
		return "", "", err
	}
	if tester.PartnerId != partnerID || tester.Email == "" {
		return "", "", ErrTestMismatch
	}
	var scopes []string
	if proof, ok := domainProofFor(conn.Protocol, conn.Issuer); ok {
		scopes = proof.scopes
	}
	return s.begin(ctx, conn, tester.Email, callbackURL, scopes, userID)
}

// completeTest records domain evidence from the test token when the issuer
// grants it, then requires the asserted email to be the tester's own inside a
// domain the partner holds, and marks the connection tested. A failed proof
// matters only when the domain is not held some other way.
func (s *Service) completeTest(ctx context.Context, conn *connection, testerID int, a *port.IdentityAssertion) error {
	tester, err := s.Users.GetUserById(testerID)
	if err != nil {
		return err
	}
	email := normalizeEmail(a.Email)
	if tester.PartnerId != conn.PartnerID || email == "" || normalizeEmail(tester.Email) != email {
		return ErrTestMismatch
	}
	var proofErr error
	if proof, ok := domainProofFor(conn.Protocol, conn.Issuer); ok && a.AccessToken != "" {
		proofErr = s.proveDomain(ctx, conn.PartnerID, int64(testerID), email, proof.method, a)
	}
	if err := s.checkIdentityDomain(ctx, conn, a); err != nil {
		if proofErr != nil {
			return proofErr
		}
		return err
	}
	if _, err := s.query(ctx).Query(ctx, qMarkTested, testerID, conn.PartnerID, conn.ID); err != nil {
		return fmt.Errorf("sso: mark tested: %w", err)
	}
	return nil
}

// proveDomain records method evidence for the partner domain the email
// belongs to. A domain the partner has not registered is skipped; a failed
// proof is returned.
func (s *Service) proveDomain(ctx context.Context, partnerID, userID int64, email, method string, a *port.IdentityAssertion) error {
	if s.Domains == nil {
		return nil
	}
	name, ok := domain.DomainName(domain.DomainFromEmail(email))
	if !ok {
		return ErrEmailNotAllowed
	}
	res, err := s.query(ctx).Query(ctx, qPartnerDomains, partnerID)
	if err != nil {
		return err
	}
	for _, row := range res.Rows {
		stored := common.AsString(row[0])
		if candidate, ok := domain.DomainName(stored); !ok || !domain.CoveredBy(name, candidate) {
			continue
		}
		_, err := s.Domains.Verify(ctx, partnerID, userID, stored, method, domain.DomainProof{
			AccessToken: a.AccessToken, Email: email, EmailVerified: a.EmailVerified, HostedDomain: a.HostedDomain})
		if err != nil {
			return fmt.Errorf("sso: prove %s: %w", stored, err)
		}
	}
	return nil
}

// Activate makes a tested connection the partner's active one. A connection
// it replaces is disabled and the sessions it signed in are revoked, and
// provisioned users' groups are mapped through the new connection.
func (s *Service) Activate(ctx context.Context, partnerID int64, userID int, connectionID int64) error {
	conn, err := s.connection(ctx, partnerID, connectionID)
	if err != nil {
		return err
	}
	if !conn.Tested {
		return ErrNotTested
	}
	if s.Domains == nil {
		return ErrNoIdentityDomain
	}
	held, err := s.Domains.Domains(ctx, partnerID, domain.IdentityMethods())
	if err != nil {
		return err
	}
	if len(held) == 0 {
		return ErrNoIdentityDomain
	}
	tx, err := s.DB.BeginTx(ctx, allQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if _, err := tx.Query(ctx, qLockConnections, partnerID); err != nil {
		return fmt.Errorf("sso: lock connections: %w", err)
	}
	replaced, err := tx.Query(ctx, qDeactivateOthers, userID, partnerID, connectionID)
	if err != nil {
		return fmt.Errorf("sso: deactivate others: %w", err)
	}
	for _, row := range replaced.Rows {
		if _, err := tx.Query(ctx, qEndProviderRoles, partnerID, common.AsInt64(row[0])); err != nil {
			return fmt.Errorf("sso: end replaced connection roles: %w", err)
		}
	}
	activated, err := tx.Query(ctx, qActivate, userID, partnerID, connectionID)
	if err != nil {
		return fmt.Errorf("sso: activate: %w", err)
	}
	if len(activated.Rows) == 0 {
		return ErrNotTested
	}
	provisioned, err := tx.Query(ctx, qActiveSCIMUsers, partnerID)
	if err != nil {
		return fmt.Errorf("sso: provisioned users: %w", err)
	}
	for _, row := range provisioned.Rows {
		if err := syncGroupRoles(ctx, tx, partnerID, int(common.AsInt64(row[0]))); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("sso: commit activation: %w", err)
	}
	committed = true
	if len(replaced.Rows) > 0 {
		return s.revokeTenantSessions(ctx, partnerID)
	}
	return nil
}

// Disable stops routing to the connection at once. Disabling the active
// connection revokes the sessions the partner's identity provider signed in.
func (s *Service) Disable(ctx context.Context, partnerID int64, userID int, connectionID int64) error {
	if partnerID <= 0 || connectionID <= 0 {
		return ErrConnectionNotFound
	}
	tx, err := s.DB.BeginTx(ctx, allQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if _, err := tx.Query(ctx, qLockConnections, partnerID); err != nil {
		return fmt.Errorf("sso: lock connections: %w", err)
	}
	// Read under the lock: a concurrent activation decides whether sessions go.
	current, err := tx.Query(ctx, qConnection, partnerID, connectionID)
	if err != nil {
		return err
	}
	if len(current.Rows) != 1 {
		return ErrConnectionNotFound
	}
	wasActive := connectionFromRow(current.Rows[0]).Status == StatusActive
	res, err := tx.Query(ctx, qDisable, userID, partnerID, connectionID)
	if err != nil {
		return fmt.Errorf("sso: disable: %w", err)
	}
	if _, err := tx.Query(ctx, qEndProviderRoles, partnerID, connectionID); err != nil {
		return fmt.Errorf("sso: end disabled connection roles: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("sso: commit disable: %w", err)
	}
	committed = true
	if len(res.Rows) == 0 || !wasActive {
		return nil
	}
	return s.revokeTenantSessions(ctx, partnerID)
}

// revokeTenantSessions signs out every member of the partner holding a
// session from its identity provider. Every user is attempted.
func (s *Service) revokeTenantSessions(ctx context.Context, partnerID int64) error {
	res, err := s.query(ctx).Query(ctx, qTenantSessionUsers, partnerID)
	if err != nil {
		return fmt.Errorf("sso: tenant sessions: %w", err)
	}
	var errs []error
	for _, row := range res.Rows {
		userID := int(common.AsInt64(row[0]))
		if err := s.Users.LogoutEverywhere(userID); err != nil {
			errs = append(errs, fmt.Errorf("sso: sign out user %d: %w", userID, err))
		}
		if err := s.Users.RevokeAccessTokens(userID); err != nil {
			errs = append(errs, fmt.Errorf("sso: revoke access of user %d: %w", userID, err))
		}
	}
	return errors.Join(errs...)
}

func nullable(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
