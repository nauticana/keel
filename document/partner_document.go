package document

import (
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/dms"
)

// PartnerDocument is one partner_document row. Content is filled by Read and
// Open from the document's component attributes.
type PartnerDocument struct {
	ID             int64
	ContRepID      string
	DocKey         string
	PartnerID      int64
	UserID         int64 // 0 means the partner itself
	DocumentType   string
	Title          string
	FileName       string
	VersionNo      int
	DocumentNumber string
	ExpiresOn      time.Time
	OriginIP       string
	UploadedBy     int64
	UploadedAt     time.Time
	Status         string
	ReviewerID     int64
	ReviewedAt     time.Time
	ReviewerNotes  string
	SupersededAt   time.Time
	RetiredAt      time.Time
	PurgedAt       time.Time
	Content        *dms.Component
}

func documentFromRow(r []any) *PartnerDocument {
	return &PartnerDocument{
		ID: common.AsInt64(r[0]), ContRepID: common.AsString(r[1]), DocKey: common.AsString(r[2]),
		PartnerID: common.AsInt64(r[3]), DocumentType: common.AsString(r[4]), UserID: optionalID(r[5]),
		Title: common.AsString(r[6]), FileName: common.AsString(r[7]), VersionNo: int(common.AsInt64(r[8])),
		DocumentNumber: common.AsString(r[9]), ExpiresOn: common.AsTime(r[10]), OriginIP: common.AsString(r[11]),
		UploadedBy: optionalID(r[12]), UploadedAt: common.AsTime(r[13]), Status: common.AsString(r[14]),
		ReviewerID: optionalID(r[15]), ReviewedAt: common.AsTime(r[16]), ReviewerNotes: common.AsString(r[17]),
		SupersededAt: common.AsTime(r[18]), RetiredAt: common.AsTime(r[19]), PurgedAt: common.AsTime(r[20]),
	}
}

// optionalID reads a nullable id column; NULL is 0.
func optionalID(v any) int64 {
	id, _ := common.AsInt64OK(v)
	return id
}
