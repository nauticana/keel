package storage

import (
	"context"
	"fmt"
)

// CheckSigning mints a throwaway signed URL so a runtime that cannot sign
// fails at start-up or in a health check rather than on the first preview.
// It makes no object request; the file backend always fails (ErrUnsupported).
func CheckSigning(ctx context.Context, s ObjectStorage) error {
	if s == nil {
		return fmt.Errorf("storage: no backend to sign with")
	}
	_, err := s.GetSignedURL(ctx, "keel-signing-check", 60)
	return err
}
