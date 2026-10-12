package klaviyo

import (
	"regexp"
	"time"
)

// Event is one metric occurrence for a profile, created or merged by identifier.
// UniqueID makes a resend the same event, so a retry never double counts.
type Event struct {
	Metric     string
	UniqueID   string
	Time       time.Time
	Properties map[string]any
	Profile    Profile
}

// Profile needs at least one of Email, PhoneNumber or ExternalID.
type Profile struct {
	Email       string    `json:"email,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	ExternalID  string    `json:"external_id,omitempty"`
	FirstName   string    `json:"first_name,omitempty"`
	LastName    string    `json:"last_name,omitempty"`
	Location    *Location `json:"location,omitempty"`
}

type Location struct {
	Address1 string `json:"address1,omitempty"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"`
	Zip      string `json:"zip,omitempty"`
}

var e164 = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)

// IsE164 reports whether phone is an E.164 number; Klaviyo refuses the whole
// event over any other phone format.
func IsE164(phone string) bool { return e164.MatchString(phone) }
