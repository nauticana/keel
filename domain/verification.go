package domain

import (
	"time"

	"github.com/nauticana/keel/common"
)

// Verification is one partner_domain_verification row. It is current while
// LapsedAt and CancelledAt are zero.
type Verification struct {
	PartnerID     int64     `json:"partnerId"`
	DomainURL     string    `json:"domainUrl"`
	VerifiedAt    time.Time `json:"verifiedAt"`
	DomainName    string    `json:"domainName"`
	Method        string    `json:"method"`
	VerifiedBy    int64     `json:"verifiedBy"`
	EvidenceRef   string    `json:"evidenceRef,omitempty"`
	LastCheckedAt time.Time `json:"lastCheckedAt"`
	FailingSince  time.Time `json:"failingSince,omitzero"`
	LastError     string    `json:"lastError,omitempty"`
	LapsedAt      time.Time `json:"lapsedAt,omitzero"`
	CancelledAt   time.Time `json:"cancelledAt,omitzero"`
	CancelledBy   int64     `json:"cancelledBy,omitempty"`
}

// Current reports whether the evidence has neither lapsed nor been cancelled.
func (v *Verification) Current() bool { return v.LapsedAt.IsZero() && v.CancelledAt.IsZero() }

func verificationFromRow(r []any) *Verification {
	return &Verification{
		PartnerID: common.AsInt64(r[0]), DomainURL: common.AsString(r[1]), VerifiedAt: common.AsTime(r[2]),
		DomainName: common.AsString(r[3]), Method: common.AsString(r[4]), VerifiedBy: common.AsInt64(r[5]),
		EvidenceRef: common.AsString(r[6]), LastCheckedAt: common.AsTime(r[7]), FailingSince: common.AsTime(r[8]),
		LastError: common.AsString(r[9]), LapsedAt: common.AsTime(r[10]), CancelledAt: common.AsTime(r[11]),
		CancelledBy: common.AsInt64(r[12]),
	}
}
