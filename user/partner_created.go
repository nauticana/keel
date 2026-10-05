package user

// PartnerCreated tells the client where to go after a partner is created.
// PaymentRequired means the plan activates at checkout: PaymentURL when a
// checkout client is wired, else the application's billing page.
type PartnerCreated struct {
	PartnerID       int64  `json:"partnerId"`
	PlanID          string `json:"planId"`
	PaymentRequired bool   `json:"paymentRequired"`
	PaymentURL      string `json:"paymentUrl,omitempty"`
}
