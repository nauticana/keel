// Package document is the client-application layer over dms: partner-owned
// documents with a review workflow, recorded in partner_document rows.
package document

import "errors"

var (
	ErrNotFound       = errors.New("document: not found")
	ErrUnknownType    = errors.New("document: unknown document type")
	ErrMediaType      = errors.New("document: this kind of file cannot be stored as this type")
	ErrTooLarge       = errors.New("document: file exceeds the type's size limit")
	ErrTenantMismatch = errors.New("document: repository belongs to another partner")
	ErrInvalidState   = errors.New("document: operation not allowed in the document's status")
)

const (
	StatusPending    = "P"
	StatusApproved   = "Y"
	StatusRejected   = "N"
	StatusSuperseded = "X"
	StatusRetired    = "R"

	// DataComponent is the single component a partner document has.
	DataComponent = "data"
)
