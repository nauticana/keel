package port

import "context"

// MessageDispatcher delivers a notification to a single channel for a
// single user. Implementations are channel-specific: an email
// dispatcher resolves userID -> email and sends via SMTP/API; a push
// dispatcher fans out to active device_token rows and sends via
// FCM/APNs; an SMS dispatcher resolves userID -> phone and sends via
// Twilio or Telnyx.
//
// An address-based channel (email, SMS) returns ErrNotificationNoAddress when
// the user has no address on it; a fan-out channel with no active devices
// returns nil. Other errors are transport failures to retry or alert on.
//
// PushProvider is a deprecated alias retained so legacy consumers
// continue to compile during migration. New code should depend on
// MessageDispatcher directly.
type MessageDispatcher interface {
	// email or phone resolved from userID
	Dispatch(ctx context.Context, userID int, title, body string, data map[string]string) error
	// to is actual email or phone
	Send(ctx context.Context, to string, title, body string, data map[string]string) error
}

// TypedMessageDispatcher is a user-addressed channel that also receives the
// notification type; LocalNotificationService calls DispatchTyped instead of
// Dispatch when a channel implements it.
type TypedMessageDispatcher interface {
	MessageDispatcher
	DispatchTyped(ctx context.Context, userID int, notificationType, title, body string, data map[string]string) error
}

// PushProvider is the legacy name for MessageDispatcher kept as a
// type alias so v0.4.x code continues to satisfy the contract.
// Deprecated: use MessageDispatcher.
type PushProvider = MessageDispatcher
