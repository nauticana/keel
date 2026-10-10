package user

import "time"

// SessionDevice is where a session signs in or refreshes from.
type SessionDevice struct {
	UserAgent string
	ClientIP  string // trusted client IP
	// DeviceSecret is the device cookie's value; empty when the client sent none.
	DeviceSecret string
}

// ActiveSession is a live sign-in session of a user.
type ActiveSession struct {
	ID           int64     `json:"id"`
	UserAgent    string    `json:"userAgent"`
	ClientIP     string    `json:"clientIp"`
	SignInMethod string    `json:"signInMethod"`
	CreatedAt    time.Time `json:"createdAt"`
	LastSeenAt   time.Time `json:"lastSeenAt"`
	Current      bool      `json:"current"`
}
