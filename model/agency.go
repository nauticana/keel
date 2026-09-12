package model

import "time"

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

// Active reports whether the agency may trade: approved and not suspended.
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
