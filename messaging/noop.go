package messaging

import (
	"context"

	"github.com/nauticana/keel/port"
)

// NoOpPublisher drops every Publish. Selected only by the explicit
// messaging_mode=noop so a brokerless deployment is a deliberate,
// greppable config value rather than a missing one.
type NoOpPublisher struct{}

func (NoOpPublisher) Publish(context.Context, string, []byte, map[string]string) error { return nil }
func (NoOpPublisher) Close() error                                                     { return nil }

var _ port.MessagePublisher = NoOpPublisher{}
