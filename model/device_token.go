package model

// Device platform codes stored in device_token.platform.
const (
	DevicePlatformiOS     = "I"
	DevicePlatformAndroid = "A"
	DevicePlatformWeb     = "W"
)

// DeviceToken is a registered push endpoint for a user. Returned by
// UserService.ListActiveDeviceTokens; persisted in the device_token table.
type DeviceToken struct {
	ID          int64
	UserID      int
	Platform    string // DevicePlatform* constant
	Token       string
	AppVersion  string
	DeviceModel string
	IsActive    bool
	CreatedAt   string
	LastSeenAt  string
}

// PushProvider is the deprecated alias for the push channel of
// MessageDispatcher. It exists for one release so existing callers that
// store the FCM provider in a *PushProvider field compile unchanged. New
// code should depend on MessageDispatcher (any channel) or wire directly
// into LocalNotificationService.Register("push", provider).
//
// FCM/APNs implementations fan out to every active device_token row for
// the user. The provider is responsible for deactivating stale tokens
// (e.g. FCM "registration-token-not-registered"). Returning nil when
// there are no active tokens is correct — "nobody to notify" is not an
// error.
//
// Deprecated: use MessageDispatcher.
//type PushProvider = MessageDispatcher
