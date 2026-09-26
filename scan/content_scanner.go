package scan

import (
	"context"
	"errors"
)

// ErrContentRejected is returned by a ContentScanner for malicious content;
// the caller refuses the request before anything is stored.
var ErrContentRejected = errors.New("content rejected by scanner")

// ContentScanner is the malware-scanning port. Callers scan synchronously
// before committing content.
type ContentScanner interface {
	Scan(ctx context.Context, content []byte) error
}
