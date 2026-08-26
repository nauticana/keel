package model

import "time"

type TableChangeLog struct {
	ID        int64
	TableName string
	RecordKey string
	Action    string
	DataHash  string
	OldData   map[string]any
	// PartnerID / OwnerUserID snapshot the changed row's partner_id / user_id
	// at write time: the source row may be gone or re-homed by the time the
	// log is read, so scope cannot be re-derived by joining back.
	PartnerID   int64
	OwnerUserID int
	CreatedAt   time.Time
	CreatedBy   int
}

// InScope reports whether the row is visible to a caller with the given
// scope; 0 means unrestricted.
func (c *TableChangeLog) InScope(partnerID int64, ownerID int) bool {
	return (partnerID == 0 || c.PartnerID == partnerID) &&
		(ownerID == 0 || c.OwnerUserID == ownerID)
}
