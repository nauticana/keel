package notify

import (
	"context"
	"strings"

	"github.com/nauticana/keel/dispatcher"
	"github.com/nauticana/keel/port"
)

// RecipientAddressable is a Queue.Addressable that keeps email and SMS only
// when the user has that address on file; other channels are always kept.
func RecipientAddressable(recipients port.RecipientResolver) func(ctx context.Context, userID int, channel string) (bool, error) {
	return func(_ context.Context, userID int, channel string) (bool, error) {
		var (
			address string
			err     error
		)
		switch channel {
		case dispatcher.EmailChannel:
			address, err = recipients.EmailFor(userID)
		case dispatcher.SMSChannel:
			address, err = recipients.PhoneFor(userID)
		default:
			return true, nil
		}
		return strings.TrimSpace(address) != "", err
	}
}
