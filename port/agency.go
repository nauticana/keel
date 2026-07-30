package port

import (
	"context"
	"errors"
	"time"
)

var (
	ErrAgencyNotFound       = errors.New("agency: not found")
	ErrNotClientOwner       = errors.New("agency: caller does not own the client partner")
	ErrDelegationExists     = errors.New("agency: client already has an active delegation")
	ErrSelfDelegation       = errors.New("agency: a partner cannot delegate to itself")
	ErrAgencyNotApproved    = errors.New("agency: this agency is awaiting approval")
	ErrAgencySuspended      = errors.New("agency: this agency is suspended")
	ErrNoPartnerYet         = errors.New("agency: finish setting up your business before accepting")
	ErrInviteExpired        = errors.New("agency: invitation has expired")
	ErrInvalidBillingModel  = errors.New("agency: billing model must be referral or wholesale")
	ErrWholesaleNotAllowed  = errors.New("agency: wholesale billing is not enabled for this agency")
	ErrCommissionRateAbsent = errors.New("agency: no valid commission rate is configured")
	ErrInvalidCommission    = errors.New("agency: invalid commission source")
	ErrPayoutDestination    = errors.New("agency: payout destination is not active and fully onboarded")
	ErrTxQueryCatalog       = errors.New("agency: transaction cannot bind an agency query catalog")
)

// AgencyService runs the agency profile, invitation, delegation and
// per-client commercial-model lifecycle. The managed generic entity is a
// business_partner; applications that manage a narrower entity add an
// extension table with a real FK to the invitation or delegation.
type AgencyService interface {
	AddClients(ctx context.Context, agencyPartnerID int64, clients []AgencyClientInput) (int, error)
	ListClients(ctx context.Context, agencyPartnerID int64) ([]AgencyClient, error)
	Invite(ctx context.Context, agencyPartnerID, invitationID int64) (string, error)
	CancelClient(ctx context.Context, agencyPartnerID, invitationID int64) error
	InviteInfo(ctx context.Context, token string) (*AgencyInvite, error)
	AcceptInvite(ctx context.Context, token string, userID, clientPartnerID int64) error
	ClientDelegation(ctx context.Context, clientPartnerID int64) (*AgencyDelegation, error)
	RevokeDelegation(ctx context.Context, clientPartnerID, callerPartnerID, callerUserID int64) error
	SetBillingModel(ctx context.Context, agencyPartnerID, clientPartnerID int64, model string) error
	CountActiveDelegations(ctx context.Context, agencyPartnerID int64) (int, error)
	Enroll(ctx context.Context, agencyPartnerID, userID int64) error
	Profile(ctx context.Context, agencyPartnerID int64) (*AgencyProfile, error)
	Approve(ctx context.Context, agencyPartnerID int64) error
	Earnings(ctx context.Context, agencyPartnerID int64) (*AgencyEarnings, error)
	PayoutProfile(ctx context.Context, agencyPartnerID, userID int64) (*AgencyPayoutProfile, []AgencyPayoutDestination, error)
	SetPayoutProfile(ctx context.Context, agencyPartnerID, userID, userBankInfoID int64) error
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
	Recognize(ctx context.Context, tx TxQueryService, source AgencyCommissionSource) error
}

type AgencyCommissionLedger interface {
	PromoteHeld(ctx context.Context) error
}

type AgencyCommissionSource struct {
	InvoiceLinePaymentID int64
	ClientPartnerID      int64
	PeriodStart          time.Time
	PeriodEnd            time.Time
	GrossAmountMinor     int64
	Currency             string
	EarnedAt             time.Time
}

type AgencyProfile struct {
	AgencyPartnerID  int64      `json:"agencyPartnerId"`
	WholesaleAllowed bool       `json:"wholesaleAllowed"`
	DefaultRateBP    int        `json:"defaultCommissionRateBp,omitempty"`
	ApprovedAt       *time.Time `json:"approvedAt,omitempty"`
	Suspended        bool       `json:"suspended"`
}

func (p *AgencyProfile) Active() bool {
	return p != nil && p.ApprovedAt != nil && !p.Suspended
}

type AgencyClientInput struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Website string `json:"website"`
}

type AgencyClient struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name"`
	Email           string     `json:"email,omitempty"`
	Website         string     `json:"website,omitempty"`
	Status          string     `json:"status"`
	ClientPartnerID int64      `json:"clientPartnerId,omitempty"`
	AcceptedBy      int64      `json:"acceptedBy,omitempty"`
	InvitedAt       *time.Time `json:"invitedAt,omitempty"`
	AcceptedAt      *time.Time `json:"acceptedAt,omitempty"`
	Expired         bool       `json:"expired,omitempty"`
	BillingModel    string     `json:"billingModel,omitempty"`
}

type AgencyInvite struct {
	InvitationID int64  `json:"invitationId"`
	AgencyName   string `json:"agencyName"`
	ClientName   string `json:"clientName"`
	Status       string `json:"status"`
	Expired      bool   `json:"expired,omitempty"`
}

type AgencyDelegation struct {
	ID              int64     `json:"id"`
	ClientPartnerID int64     `json:"clientPartnerId"`
	ClientName      string    `json:"clientName"`
	AgencyPartnerID int64     `json:"agencyPartnerId"`
	AgencyName      string    `json:"agencyName"`
	BillingModel    string    `json:"billingModel,omitempty"`
	GrantedAt       time.Time `json:"grantedAt"`
}

type AgencyEarnings struct {
	Balances      []AgencyEarningsBalance `json:"balances"`
	Entries       []AgencyEarningEntry    `json:"entries"`
	Payouts       []AgencyPayout          `json:"payouts"`
	PayingClients int                     `json:"payingClients"`
}

type AgencyEarningsBalance struct {
	Currency  string `json:"currency"`
	HeldMinor int64  `json:"heldMinor"`
	DueMinor  int64  `json:"dueMinor"`
	PaidMinor int64  `json:"paidMinor"`
}

type AgencyEarningEntry struct {
	ID          int64     `json:"id"`
	ClientName  string    `json:"clientName"`
	PeriodStart time.Time `json:"periodStart"`
	PeriodEnd   time.Time `json:"periodEnd"`
	AmountMinor int64     `json:"amountMinor"`
	Currency    string    `json:"currency"`
	EntryType   string    `json:"entryType"`
	Status      string    `json:"status"`
	EarnedAt    time.Time `json:"earnedAt"`
}

type AgencyPayout struct {
	ID          int64      `json:"id"`
	AmountMinor int64      `json:"amountMinor"`
	Currency    string     `json:"currency"`
	Status      string     `json:"status"`
	CutoffAt    time.Time  `json:"cutoffAt"`
	PaidAt      *time.Time `json:"paidAt,omitempty"`
}

type AgencyPayoutProfile struct {
	AgencyPartnerID   int64  `json:"agencyPartnerId"`
	UserBankInfoID    int64  `json:"userBankInfoId"`
	CountryCode       string `json:"countryCode"`
	Currency          string `json:"currency"`
	Provider          string `json:"provider"`
	ProviderAccountID string `json:"providerAccountId"`
	Status            string `json:"status"`
}

type AgencyPayoutDestination struct {
	UserBankInfoID    int64  `json:"userBankInfoId"`
	CountryCode       string `json:"countryCode"`
	Currency          string `json:"currency"`
	Provider          string `json:"provider"`
	ProviderAccountID string `json:"providerAccountId"`
}
