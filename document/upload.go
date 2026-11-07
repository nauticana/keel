package document

import (
	"io"
	"time"
)

// Upload is one file to store as a new document version.
type Upload struct {
	PartnerID int64
	Subject
	DocumentType   string
	Title          string
	FileName       string
	DocumentNumber string
	ExpiresOn      time.Time
	Language       string // BCP 47 tag, at most 8 characters
	OriginIP       string
	UploadedBy     int64
	Body           io.Reader
}
