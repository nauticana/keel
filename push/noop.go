package push

import (
	"context"

	"github.com/nauticana/keel/port"
)

// NoOpPushProvider drops every Dispatch call. Wired for non-mobile consumers and for local development where FCM credentials are unavailable. Always safe; never errors.
type NoOpPushProvider struct{}

func (NoOpPushProvider) Dispatch(_ context.Context, _ int, _, _ string, _ map[string]string) error {
	return nil
}

func (NoOpPushProvider) Send(_ context.Context, _, _, _ string, _ map[string]string) error {
	return nil
}

var _ port.MessageDispatcher = NoOpPushProvider{}
