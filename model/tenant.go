package model

// Tenant relationships: a partner the user belongs to, a client partner reached
// through an agency delegation, or the partner an API key is bound to.
const (
	TenantOwn       = "own"
	TenantDelegated = "delegated"
	TenantAPIKey    = "api_key"
)

// TenantCaller is who asks to act: a signed-in user or an API key's partner.
// Exactly one is set.
type TenantCaller struct {
	UserID          int64
	APIKeyPartnerID int64
}

// Tenant is a partner a caller may act in. Level, DelegationID and
// AgencyPartnerID are set only on a delegated tenant.
type Tenant struct {
	PartnerID       int64  `json:"partnerId"`
	Name            string `json:"name"`
	Relationship    string `json:"relationship"`
	Level           string `json:"level,omitempty"`
	DelegationID    int64  `json:"delegationId,omitempty"`
	AgencyPartnerID int64  `json:"agencyPartnerId,omitempty"`
}
