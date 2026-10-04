package port

import (
	"context"
	"errors"

	"github.com/nauticana/keel/model"
)

var (
	ErrAgencyNotFound          = errors.New("agency: not found")
	ErrNotClientOwner          = errors.New("agency: caller does not own the client partner")
	ErrDelegationExists        = errors.New("agency: client already has an active delegation")
	ErrSelfDelegation          = errors.New("agency: a partner cannot delegate to itself")
	ErrAgencyNotApproved       = errors.New("agency: this agency is awaiting approval")
	ErrAgencySuspended         = errors.New("agency: this agency is suspended")
	ErrNoPartnerYet            = errors.New("agency: finish setting up your business before accepting")
	ErrInviteExpired           = errors.New("agency: invitation has expired")
	ErrInvalidBillingModel     = errors.New("agency: billing model must be referral or wholesale")
	ErrWholesaleNotAllowed     = errors.New("agency: wholesale billing is not enabled for this agency")
	ErrCommissionRateAbsent    = errors.New("agency: no valid commission rate is configured")
	ErrInvalidCommission       = errors.New("agency: invalid commission source")
	ErrPayoutDestination       = errors.New("agency: payout destination is not active and fully onboarded")
	ErrTxQueryCatalog          = errors.New("agency: transaction cannot bind an agency query catalog")
	ErrInvalidDelegationRole   = errors.New("agency: delegation role is blank or unknown")
	ErrDuplicateDelegationRole = errors.New("agency: delegation role is listed more than once")
	ErrTooManyDelegationRoles  = errors.New("agency: too many delegation roles")
	ErrDelegationExpiryPast    = errors.New("agency: delegation expiry must be in the future")
	ErrDelegationNoAccess      = errors.New("agency: no active delegation grants this agency access")
)

// AgencyService runs the agency profile, invitation, delegation and
// per-client commercial-model lifecycle. The managed generic entity is a
// business_partner; applications that manage a narrower entity add an
// extension table with a real FK to the invitation or delegation.
type AgencyService interface {
	AddClients(ctx context.Context, agencyPartnerID int64, clients []model.AgencyClientInput) (int, error)
	ListClients(ctx context.Context, agencyPartnerID int64) ([]model.AgencyClient, error)
	Invite(ctx context.Context, agencyPartnerID, invitationID int64) (string, error)
	CancelClient(ctx context.Context, agencyPartnerID, invitationID int64) error
	InviteInfo(ctx context.Context, token string) (*model.AgencyInvite, error)
	AcceptInvite(ctx context.Context, token string, userID, clientPartnerID int64) error
	ClientDelegation(ctx context.Context, clientPartnerID int64) (*model.AgencyDelegation, error)
	RevokeDelegation(ctx context.Context, clientPartnerID, callerPartnerID, callerUserID int64) error
	// SetDelegationRoles is client-only and replaces the delegation's role set.
	// An empty set removes all access without revoking the delegation.
	SetDelegationRoles(ctx context.Context, clientPartnerID, callerPartnerID int64, grants []model.AgencyRoleGrant, callerUserID int64) error
	SetBillingModel(ctx context.Context, agencyPartnerID, clientPartnerID int64, model string) error
	CountActiveDelegations(ctx context.Context, agencyPartnerID int64) (int, error)
	Enroll(ctx context.Context, agencyPartnerID, userID int64) error
	Profile(ctx context.Context, agencyPartnerID int64) (*model.AgencyProfile, error)
	Approve(ctx context.Context, agencyPartnerID int64) error
	Earnings(ctx context.Context, agencyPartnerID int64) (*model.AgencyEarnings, error)
	PayoutProfile(ctx context.Context, agencyPartnerID, userID int64) (*model.AgencyPayoutProfile, []model.AgencyPayoutDestination, error)
	SetPayoutProfile(ctx context.Context, agencyPartnerID, userID, userBankInfoID int64) error
}

// AgencyDelegationResolver answers what an agency may do now: an active
// delegation, an approved unsuspended agency, and an unexpired role. ActiveFor
// returns only unexpired roles; HasRole returns nil or ErrDelegationNoAccess.
type AgencyDelegationResolver interface {
	ActiveFor(ctx context.Context, agencyPartnerID int64) ([]model.AgencyDelegation, error)
	HasRole(ctx context.Context, agencyPartnerID, clientPartnerID int64, role string) error
}

// AgencyRateResolver freezes the percentage assigned to one agency/client at
// first earning. The caller supplies its transaction so rate creation and the
// corresponding ledger entry commit atomically.
type AgencyRateResolver interface {
	Resolve(ctx context.Context, tx TxQueryService, agencyPartnerID, clientPartnerID int64) (int, error)
}

// AgencyCommissionRecognizer turns a paid invoice-line allocation into held
// referral earnings. The application decides which invoice lines are eligible
// and calls this inside the same provenance transaction.
type AgencyCommissionRecognizer interface {
	Recognize(ctx context.Context, tx TxQueryService, source model.AgencyCommissionSource) error
}

type AgencyCommissionLedger interface {
	PromoteHeld(ctx context.Context) error
}
