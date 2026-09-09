package push

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
	"github.com/nauticana/keel/user"
)

// NewPushProvider returns the provider selected by push_mode:
// "fcm", "apns", "fcm,apns" (PlatformRouter: iOS rows go to APNs, the rest
// to FCM) or "noop" / "" (dispatches are discarded).
func NewPushProvider(ctx context.Context, secrets secret.SecretProvider, users user.UserService, journal logger.ApplicationLogger) (port.MessageDispatcher, error) {
	switch config.Config().PushMode {
	case "fcm":
		return New(ctx, users, journal)
	case "apns":
		return NewAPNs(ctx, secrets, users, journal)
	case "fcm,apns":
		fcm, err := New(ctx, users, journal)
		if err != nil {
			return nil, err
		}
		apns, err := NewAPNs(ctx, secrets, users, journal)
		if err != nil {
			return nil, err
		}
		return NewPlatformRouter(users, fcm, apns), nil
	case "noop", "":
		return NoOpPushProvider{}, nil
	default:
		return nil, fmt.Errorf("unknown push_mode: %s", config.Config().PushMode)
	}
}
