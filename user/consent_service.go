package user

import "context"

// Consent type labels recorded in consent_event. Consumers may define
// additional custom labels; these are the canonical shared ones.
const (
	ConsentTypePrivacyPolicy = "privacy_policy"
	ConsentTypeTerms         = "terms"
	ConsentTypeCrossBorder   = "cross_border"
	ConsentTypeVideoOptIn    = "video_opt_in"
	ConsentTypeVideoSession  = "video_session"
	ConsentTypeMarketing     = "marketing"
)

// ConsentRequest represents a single consent decision being recorded.
// Use UserID when the row is tied to a registered user; otherwise the
// Email fallback is hashed and stored so the event can be linked to
// the user_account row once it is created.
type ConsentRequest struct {
	UserID          int
	Email           string // hashed internally (SHA-256); never stored plaintext
	ConsentType     string
	Consented       bool
	PolicyType      string
	PolicyRegion    string
	PolicyVersion   string
	PolicyLanguage  string
	EventRef        string // optional: reference to a domain object (e.g. ride_id for video_session)
	Region          string
	ClientIP        string
	ClientUserAgent string
}

// SignupConsent carries the consent metadata that handlers pass through
// signup flows (social login, phone OTP). Policy identification (type,
// version, region, language) plus the map of consent decisions the user
// agreed to, plus audit metadata (IP, user-agent, region). Pass nil to
// skip consent recording for a given signup.
type SignupConsent struct {
	PolicyType      string
	PolicyVersion   string
	PolicyRegion    string
	PolicyLanguage  string
	Region          string
	ClientIP        string
	ClientUserAgent string
	EventRef        string
	Consents        map[string]bool // consent_type → consented
}

// ConsentService records and queries the consent audit trail backed by
// the consent_policy and consent_event tables. Optional on LocalUserService:
// when registered and a SignupConsent is passed, signup flows record
// consent after user_account creation. When not registered or the caller
// passes nil SignupConsent, no consent recording happens.
type ConsentService interface {
	Record(ctx context.Context, req ConsentRequest) error
	RecordSignupConsents(ctx context.Context, userID int, email string, consents map[string]bool, meta ConsentRequest) error
	LatestConsent(ctx context.Context, userID int, email, consentType string) (consented bool, found bool, err error)
}
