package push

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/dispatcher"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/user"
)

// NewPushProvider returns the push provider selected by --push_mode.
// "fcm" wires the Firebase Cloud Messaging backend (requires
// GOOGLE_APPLICATION_CREDENTIALS or GCP runtime). "noop" returns a
// provider that silently discards dispatches — the default for
// non-mobile consumers.
func NewPushProvider(ctx context.Context, users user.UserService, journal logger.ApplicationLogger) (dispatcher.MessageDispatcher, error) {
	switch *common.PushMode {
	case "fcm":
		return New(ctx, users, journal)
	case "noop", "":
		return NoOpPushProvider{}, nil
	default:
		return nil, fmt.Errorf("unknown push_mode: %s", *common.PushMode)
	}
}
