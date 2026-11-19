package entitlement

// State is where a license stands at a moment: in force, in its grace period after expiry, or past grace.
type State string

const (
	StateActive  State = "active"
	StateGrace   State = "grace"
	StateExpired State = "expired"
)
