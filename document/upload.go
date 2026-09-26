package document

import (
	"io"
	"time"
)

// Upload is one file to store as a new document version.
type Upload struct {
	PartnerID      int64
	UserID         int64 // 0 means the partner itself
	DocumentType   string
	Title          string
	FileName       string
	DocumentNumber string
	ExpiresOn      time.Time
	OriginIP       string
	UploadedBy     int64
	Body           io.Reader
}
