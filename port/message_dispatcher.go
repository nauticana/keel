package port

import "context"

// MessageDispatcher delivers a notification to a single channel for a
// single user. Implementations are channel-specific: an email
// dispatcher resolves userID -> email and sends via SMTP/API; a push
// dispatcher fans out to active device_token rows and sends via
// FCM/APNs; an SMS dispatcher resolves userID -> phone and sends via
// Twilio.
//
// Returning nil when the user has no usable address for this channel
// ("no email on file", "no active devices") is correct — that is the
// channel-level no-op signal. Reserve non-nil errors for transport
// failures the caller should retry or alert on.
//
// PushProvider is a deprecated alias retained so legacy consumers
// continue to compile during migration. New code should depend on
// MessageDispatcher directly.
type MessageDispatcher interface {
	Dispatch(ctx context.Context, userID int, title, body string, data map[string]string) error
}

// PushProvider is the legacy name for MessageDispatcher kept as a
// type alias so v0.4.x code continues to satisfy the contract.
// Deprecated: use MessageDispatcher.
type PushProvider = MessageDispatcher
