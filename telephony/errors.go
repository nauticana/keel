package telephony

import (
	"errors"
	"fmt"

	"github.com/nauticana/keel/config"
)

var (
	ErrSignature = errors.New("telephony: webhook signature does not verify")
	ErrPayload   = errors.New("telephony: webhook payload is unreadable")
)

const maxSignatureBytes = 1024

func checkSize(webhook Webhook, signature string) error {
	// Checked before any signature work; handlers cap their read at the same size.
	if limit := config.Config().TelephonyMaxBodyBytes; int64(len(webhook.Body)) > limit {
		return fmt.Errorf("%w: body over telephony_max_body_bytes (%d)", ErrPayload, limit)
	}
	if len(signature) > maxSignatureBytes {
		return fmt.Errorf("%w: signature header over %d bytes", ErrSignature, maxSignatureBytes)
	}
	return nil
}
