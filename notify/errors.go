// Package notify is a durable multi-channel notification queue: Queue fans a
// notification out to one notification row per resolved channel, and Worker
// drains those rows through a port.NotificationService with lease-scoped
// retries, so a delivery survives restarts and transport outages.
package notify

import "errors"

var (
	ErrInvalidMessage = errors.New("notify: user, notification type and title are required")
	ErrInvalidChannel = errors.New("notify: notification type and channel are required")
	ErrNoSender       = errors.New("notify: worker has no Sender")
)

// Status codes for notification.status.
const (
	StatusPending    = "P"
	StatusActive     = "A"
	StatusSent       = "S"
	StatusSuppressed = "X"
	StatusFailed     = "F"
)
