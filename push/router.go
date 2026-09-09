package push

import (
	"context"
	"fmt"
	"regexp"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// tokenSender is the per-platform half of a provider: deliver to an
// already-listed set of device rows and revoke the stale ones.
type tokenSender interface {
	port.MessageDispatcher
	sendTokens(ctx context.Context, userID int, devices []model.DeviceToken, title, body string, data map[string]string) error
}

// PlatformRouter splits a user's device tokens by platform and hands each
// group to its provider (iOS → APNs, everything else → FCM).
type PlatformRouter struct {
	byPlatform map[string]tokenSender
	fallback   tokenSender
	users      user.UserService
}

func NewPlatformRouter(users user.UserService, fcm, apns tokenSender) *PlatformRouter {
	return &PlatformRouter{
		byPlatform: map[string]tokenSender{model.DevicePlatformiOS: apns},
		fallback:   fcm,
		users:      users,
	}
}

func (r *PlatformRouter) Dispatch(ctx context.Context, userID int, title, body string, data map[string]string) error {
	devices, err := r.users.ListActiveDeviceTokens(userID)
	if err != nil {
		return fmt.Errorf("push: list tokens for user %d: %w", userID, err)
	}
	groups := make(map[tokenSender][]model.DeviceToken)
	for _, d := range devices {
		groups[r.providerFor(d.Platform)] = append(groups[r.providerFor(d.Platform)], d)
	}
	var firstErr error
	for provider, group := range groups {
		if err := provider.sendTokens(ctx, userID, group, title, body, data); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Raw APNs tokens are 64 hex characters; anything else is an FCM token.
var apnsTokenShape = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func (r *PlatformRouter) Send(ctx context.Context, to, title, body string, data map[string]string) error {
	if apnsTokenShape.MatchString(to) {
		return r.byPlatform[model.DevicePlatformiOS].Send(ctx, to, title, body, data)
	}
	return r.fallback.Send(ctx, to, title, body, data)
}

func (r *PlatformRouter) providerFor(platform string) tokenSender {
	if p, ok := r.byPlatform[platform]; ok {
		return p
	}
	return r.fallback
}

var _ port.MessageDispatcher = (*PlatformRouter)(nil)
