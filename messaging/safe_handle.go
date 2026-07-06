package messaging

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/port"
)

// safeHandle runs a message handler with a panic barrier so one bad payload
// Nacks (redelivered/backed off) instead of unwinding out of the subscriber
// loop and tearing down the whole consumer.
func safeHandle(ctx context.Context, handler port.MessageHandler, msg *port.Message) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("message handler panicked: %v", r)
		}
	}()
	return handler(ctx, msg)
}
