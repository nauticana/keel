package document

import (
	"context"

	"github.com/nauticana/keel/port"
)

// Event types Review writes to outbox_event for a type with Publish set.
const (
	EventApproved = "document.approved"
	EventRejected = "document.rejected"
)

// Hooks are an application's steps for documents of one type.
type Hooks struct {
	// Approve runs before an approval is written, outside any transaction,
	// with the document's content; an error refuses the approval.
	Approve func(ctx context.Context, doc *PartnerDocument, content []byte) error
	// Stored runs in Store's transaction after the row is written; an error
	// rolls the row back and removes the objects.
	Stored func(ctx context.Context, tx port.TxQueryService, doc *PartnerDocument) error
	// Reviewed runs in Review's transaction after the decision is written; an
	// error rolls the decision back.
	Reviewed func(ctx context.Context, tx port.TxQueryService, doc *PartnerDocument) error
	// Publish writes EventApproved or EventRejected, aggregate partner_document,
	// in Review's transaction.
	Publish bool
}
