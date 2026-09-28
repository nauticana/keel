package notify

// Preference is a user's explicit choice for one notification type on one channel.
type Preference struct {
	NotificationType string
	Channel          string
	Enabled          bool
}
