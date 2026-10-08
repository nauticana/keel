package sso

import (
	"context"
	"errors"
	"fmt"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// identityProvider labels tenant links in user_external_identity.
const identityProvider = "sso"

// signIn finds or creates the account, keeps it a member of the connection's
// partner, applies the role mapping, and returns the session. An account in
// another partner, or one this partner does not create, is refused.
func (s *Service) signIn(ctx context.Context, conn *connection, a *port.IdentityAssertion) (*model.UserSession, error) {
	id := user.ExternalIdentity{
		Provider: identityProvider, Issuer: a.Issuer, Subject: a.Subject, Email: normalizeEmail(a.Email),
		EmailVerified: a.EmailVerified, HostedDomain: a.HostedDomain, FirstName: a.GivenName, LastName: a.FamilyName,
	}
	var (
		userID int
		create bool
		join   bool
	)
	linked, err := s.Users.GetUserFromExternal(id)
	switch {
	case err == nil:
		userID = linked.Id
		if join, err = s.mustJoin(conn.PartnerID, linked.PartnerId); err != nil {
			return nil, err
		}
	case errors.Is(err, user.ErrIdentityNotLinked):
		existing, err := s.Users.GetUserByEmail(id.Email)
		if err != nil {
			return nil, err
		}
		if join, err = s.mustJoin(conn.PartnerID, existing.PartnerId); err != nil {
			return nil, err
		}
		if err := s.Users.LinkExternalIdentity(existing.Id, id); err != nil {
			return nil, err
		}
		userID = existing.Id
	case errors.Is(err, user.ErrNoAccount):
		if !s.createsAccounts(conn.PartnerID) {
			return nil, ErrNoAccount
		}
		create = true
	default:
		return nil, err
	}
	if userID, err = s.commitMembership(ctx, conn, a, id, userID, create, join); err != nil {
		return nil, err
	}
	session, err := s.Users.GetUserById(userID)
	if err != nil {
		return nil, err
	}
	if session.PartnerId != conn.PartnerID {
		return nil, ErrOtherPartner
	}
	if err := s.Users.CheckSignInMethod(userID, user.SignInTenant); err != nil {
		return nil, err
	}
	session.SignInMethod, session.Provider = user.SignInTenant, identityProvider
	return session, nil
}

// mustJoin reports whether an account with current partner memberOf must
// join partnerID, which only an account without a partner may, and only when
// the partner creates accounts on first sign-in.
func (s *Service) mustJoin(partnerID, memberOf int64) (bool, error) {
	switch {
	case memberOf == partnerID:
		return false, nil
	case memberOf != 0:
		return false, ErrOtherPartner
	case s.createsAccounts(partnerID):
		return true, nil
	default:
		return false, ErrNoAccount
	}
}

// createsAccounts reads SSO_JIT_CREATE; a failed lookup creates nothing.
func (s *Service) createsAccounts(partnerID int64) bool {
	policies, err := s.Users.EffectivePolicies(partnerID)
	return err == nil && policies[user.PolicySSOJITCreate] == 1
}

// commitMembership creates or joins the account when asked and syncs the
// mapped roles, in one transaction. A user the directory provisions takes its
// roles from its groups instead.
func (s *Service) commitMembership(ctx context.Context, conn *connection, a *port.IdentityAssertion, id user.ExternalIdentity, userID int, create, join bool) (int, error) {
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
	if create || join {
		accounts, ok := s.Users.(user.TenantAccountCreator)
		if !ok {
			return 0, errors.New("sso: the user service cannot create tenant accounts")
		}
		if create {
			session, err := accounts.CreateTenantAccountTx(ctx, tx, conn.PartnerID, id)
			if errors.Is(err, user.ErrAccountExists) {
				return 0, ErrSignInFailed
			}
			if err != nil {
				return 0, err
			}
			userID = session.Id
		} else if err := accounts.JoinPartnerTx(ctx, tx, conn.PartnerID, userID); err != nil {
			if errors.Is(err, user.ErrAlreadyMember) {
				return 0, ErrOtherPartner
			}
			return 0, err
		}
	}
	managed, err := tx.Query(ctx, qSCIMManaged, conn.PartnerID, userID)
	if err != nil {
		return 0, fmt.Errorf("sso: provisioned user: %w", err)
	}
	if len(managed.Rows) == 0 {
		if err := syncRoles(ctx, tx, conn, userID, assertedClaims(a)); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("sso: commit sign-in: %w", err)
	}
	committed = true
	return userID, nil
}
