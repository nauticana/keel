package model

import "time"

// PartnerMembership is one current partner_user row for a user.
type PartnerMembership struct {
	PartnerID int64      `json:"partnerId"`
	Begda     time.Time  `json:"begda"`
	Endda     *time.Time `json:"endda,omitempty"`
}
