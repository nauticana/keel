package user

// PartnerRegistration is a signup confirmed by an emailed code. Without any
// partner field it creates only the account, and the user adds the partner
// later with CreatePartner.
type PartnerRegistration struct {
	AccountRegistration
	PartnerSetup
}
