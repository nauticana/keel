package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/pgsql"
	"github.com/nauticana/keel/port"
)

// EmailVerifiedByTenant: a partner's own identity provider asserted the
// email inside a domain the partner holds by identity-grade evidence.
const EmailVerifiedByTenant = "T"

// TenantMember is an account a partner's directory provisions.
type TenantMember struct {
	FirstName string
	LastName  string
	Email     string
}

// TenantAccountCreator creates, joins and updates the accounts a partner's
// own identity provider or directory manages, inside the caller's
// transaction. The caller has already checked that every email lies in a
// domain the partner holds.
type TenantAccountCreator interface {
	CreateTenantAccountTx(ctx context.Context, tx port.TxQueryService, partnerID int64, identity ExternalIdentity) (*model.UserSession, error)
	CreateTenantMemberTx(ctx context.Context, tx port.TxQueryService, partnerID int64, member TenantMember, join bool) (int, error)
	UpdateTenantMemberTx(ctx context.Context, tx port.TxQueryService, userID int, member TenantMember) error
	JoinPartnerTx(ctx context.Context, tx port.TxQueryService, partnerID int64, userID int) error
}

var _ TenantAccountCreator = (*LocalUserService)(nil)

// CreateTenantAccountTx creates the account, links the identity, stores the
// email as verified by the tenant and makes the account a member of partnerID.
// An identity or email that already has an account returns ErrAccountExists.
func (s *LocalUserService) CreateTenantAccountTx(ctx context.Context, tx port.TxQueryService, partnerID int64, id ExternalIdentity) (*model.UserSession, error) {
	if err := id.validate(); err != nil {
		return nil, err
	}
	local, _, err := tenantCatalogs(tx)
	if err != nil {
		return nil, err
	}
	res, err := local.Query(ctx, qUserByExternalIdentity, id.Issuer, id.Subject)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) > 0 {
		return nil, ErrAccountExists
	}
	member := TenantMember{FirstName: id.FirstName, LastName: id.LastName, Email: id.Email}
	userID, err := s.CreateTenantMemberTx(ctx, tx, partnerID, member, true)
	if err != nil {
		return nil, err
	}
	if _, err := local.Query(ctx, qLinkExternalIdentity, userID, id.Provider, id.Issuer, id.Subject); err != nil {
		if pgsql.IsUniqueViolation(err) {
			return nil, ErrAccountExists
		}
		return nil, err
	}
	session := s.newSession(userID, id.FirstName, id.LastName, normalizeEmail(id.Email), UserStatusActive, id.Provider)
	session.PhoneNumber, session.PartnerId = id.Phone, partnerID
	return session, nil
}

// CreateTenantMemberTx creates an account whose email the tenant vouches for
// and, when join is set, makes it a member of partnerID. An email that
// already has an account returns ErrAccountExists.
func (s *LocalUserService) CreateTenantMemberTx(ctx context.Context, tx port.TxQueryService, partnerID int64, m TenantMember, join bool) (int, error) {
	email := normalizeEmail(m.Email)
	if partnerID <= 0 || email == "" {
		return 0, fmt.Errorf("user: a tenant account needs a partner and an email")
	}
	local, register, err := tenantCatalogs(tx)
	if err != nil {
		return 0, err
	}
	res, err := local.Query(ctx, qUserIDByEmail, email)
	if err != nil {
		return 0, err
	}
	if len(res.Rows) > 0 {
		return 0, ErrAccountExists
	}
	userID, err := s.insertUserAccount(ctx, local, m.FirstName, m.LastName, email, "", email)
	if errors.Is(err, ErrDuplicateEmail) {
		return 0, ErrAccountExists
	}
	if err != nil {
		return 0, err
	}
	if _, err := local.Query(ctx, qMarkEmailVerified, EmailVerifiedByTenant, userID); err != nil {
		return 0, err
	}
	if join {
		if _, err := register.Query(ctx, qAddPartnerUser, partnerID, userID); err != nil {
			return 0, fmt.Errorf("user: add membership: %w", err)
		}
	}
	if _, err := local.Query(ctx, qAddUserActivity, userID, time.Now(), UserActivityCreate, "A", fmt.Sprintf("tenant:%d", partnerID), ""); err != nil {
		return 0, err
	}
	return userID, nil
}

// UpdateTenantMemberTx sets the names and, when it changes, the tenant-vouched
// email of an account. An email another account uses returns ErrAccountExists.
func (s *LocalUserService) UpdateTenantMemberTx(ctx context.Context, tx port.TxQueryService, userID int, m TenantMember) error {
	email := normalizeEmail(m.Email)
	if userID <= 0 || email == "" {
		return fmt.Errorf("user: a tenant account needs an id and an email")
	}
	local, _, err := tenantCatalogs(tx)
	if err != nil {
		return err
	}
	if _, err := local.Query(ctx, qUpdateTenantMember, m.FirstName, m.LastName, email, email, email, userID); err != nil {
		if errors.Is(classifyUniqueViolation(err), ErrDuplicateEmail) {
			return ErrAccountExists
		}
		return err
	}
	return nil
}

// JoinPartnerTx makes an existing account without a current membership a
// member of partnerID; a member of any partner returns ErrAlreadyMember.
func (s *LocalUserService) JoinPartnerTx(ctx context.Context, tx port.TxQueryService, partnerID int64, userID int) error {
	if partnerID <= 0 || userID <= 0 {
		return ErrNoMembership
	}
	_, register, err := tenantCatalogs(tx)
	if err != nil {
		return err
	}
	if _, err := register.Query(ctx, qAddPartnerUser, partnerID, userID); err != nil {
		if pgsql.IsExclusionViolation(err) {
			return ErrAlreadyMember
		}
		return fmt.Errorf("user: add membership: %w", err)
	}
	return nil
}

func tenantCatalogs(tx port.TxQueryService) (port.QueryService, port.QueryService, error) {
	catalog, ok := tx.(port.TxQueryCatalog)
	if !ok {
		return nil, nil, errors.New("user: the transaction cannot bind the user query catalogs")
	}
	return catalog.QueryService("user.local", LocalUserQueries), catalog.QueryService("user.register", registerQueries), nil
}
