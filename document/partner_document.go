package document

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/dms"
	"github.com/nauticana/keel/outbox"
	"github.com/nauticana/keel/port"
)

// PartnerDocument is one partner_document row. Content is filled by Read and
// Open from the document's component attributes.
type PartnerDocument struct {
	ID        int64  `json:"id,string"`
	ContRepID string `json:"contrep_id"`
	DocKey    string `json:"doc_key"`
	PartnerID int64  `json:"partner_id"`
	Subject
	DocumentType   string         `json:"document_type"`
	Title          string         `json:"title"`
	FileName       string         `json:"file_name"`
	VersionNo      int32          `json:"version_no"`
	DocumentNumber string         `json:"document_number,omitempty"`
	ExpiresOn      time.Time      `json:"expires_on,omitzero"`
	Language       string         `json:"language,omitempty"`
	OriginIP       string         `json:"origin_ip,omitempty"`
	UploadedBy     int64          `json:"uploaded_by,omitzero"`
	UploadedAt     time.Time      `json:"uploaded_at,omitzero"`
	Status         string         `json:"status"`
	ReviewerID     int64          `json:"reviewer_id,omitzero"`
	ReviewedAt     time.Time      `json:"reviewed_at,omitzero"`
	ReviewerNotes  string         `json:"reviewer_notes,omitempty"`
	SupersededAt   time.Time      `json:"superseded_at,omitzero"`
	RetiredAt      time.Time      `json:"retired_at,omitzero"`
	PurgedAt       time.Time      `json:"purged_at,omitzero"`
	Content        *dms.Component `json:"-"`
}

func documentFromRow(r []any) *PartnerDocument {
	return &PartnerDocument{
		ID: common.AsInt64(r[0]), ContRepID: common.AsString(r[1]), DocKey: common.AsString(r[2]),
		PartnerID: common.AsInt64(r[3]), DocumentType: common.AsString(r[4]), Subject: Subject{UserID: optionalID(r[5]), SubjectKey: common.AsString(r[21])},
		Title: common.AsString(r[6]), FileName: common.AsString(r[7]), VersionNo: common.AsInt32(r[8]),
		DocumentNumber: common.AsString(r[9]), ExpiresOn: common.AsTime(r[10]), OriginIP: common.AsString(r[11]),
		UploadedBy: optionalID(r[12]), UploadedAt: common.AsTime(r[13]), Status: common.AsString(r[14]),
		ReviewerID: optionalID(r[15]), ReviewedAt: common.AsTime(r[16]), ReviewerNotes: common.AsString(r[17]),
		SupersededAt: common.AsTime(r[18]), RetiredAt: common.AsTime(r[19]), PurgedAt: common.AsTime(r[20]), Language: common.AsString(r[22]),
	}
}

// optionalID reads a nullable id column; NULL is 0.
func optionalID(v any) int64 {
	id, _ := common.AsInt64OK(v)
	return id
}

// publish writes the review outcome to the outbox in the review transaction.
// The payload names the document and its decision only; a consumer reads the
// rest through the service.
func (doc *PartnerDocument) publish(ctx context.Context, tx port.TxQueryService) error {
	payload, err := json.Marshal(struct {
		ID int64 `json:"id,string"`
		Subject
		DocumentType string    `json:"document_type"`
		VersionNo    int32     `json:"version_no"`
		Status       string    `json:"status"`
		ReviewerID   int64     `json:"reviewer_id"`
		ReviewedAt   time.Time `json:"reviewed_at"`
	}{doc.ID, doc.Subject, doc.DocumentType, doc.VersionNo, doc.Status, doc.ReviewerID, doc.ReviewedAt})
	if err != nil {
		return err
	}
	event := EventRejected
	if doc.Status == StatusApproved {
		event = EventApproved
	}
	_, err = outbox.EnqueueTx(ctx, tx, outbox.Event{PartnerID: doc.PartnerID, AggregateType: "partner_document",
		AggregateID: strconv.FormatInt(doc.ID, 10), EventType: event, Payload: string(payload)})
	return err
}
