package port

// RecipientResolver is the narrow port that channel dispatchers use
// to resolve a userID to its channel-specific address. Email
// dispatchers ask for EmailFor; SMS dispatchers ask for PhoneFor.
//
// Splitting this out of UserService means dispatcher implementations
// don't need to import the user package — eliminating the cyclic-
// import risk that previously sat between dispatcher and user, and
// freeing consumers to slot in a thinner address-only resolver
// (e.g. one backed by a recipient cache) without exposing the full
// user-service surface.
//
// Implementations return ("", nil) — empty address, no error — when
// the user has no contact for that channel. Dispatchers treat that
// as "nobody to notify" and short-circuit the channel-level no-op.
// Reserve non-nil errors for transport failures the caller should
// retry on (DB outage, ID lookup failure).
type RecipientResolver interface {
	// EmailFor returns the user's normalized email address, or "" when
	// the user has no email on file (deleted, social account, OTP-only).
	EmailFor(userID int) (string, error)

	// PhoneFor returns the user's E.164 phone number, or "" when the
	// user has no phone on file.
	PhoneFor(userID int) (string, error)
}
