package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// UserSession is the JWT claim payload AND the in-process session shape.
//
// Wire-format note (v0.4.3 perf): Subject, Issuer, ExpiresAt, IssuedAt
// are tagged `json:"-"` so they are NOT emitted alongside the standard
// `sub`, `iss`, `exp`, `iat` claims that the embedded
// jwt.RegisteredClaims already carries. The four duplicate fields
// previously added ~74 bytes (~30%) to every token. SyncTimestamps
// populates the embedded claims from these in-Go mirrors before
// signing; ParseJWT (in service/user_service.go) hydrates the
// mirrors back from the validated RegisteredClaims after parse. The
// public Go API surface is unchanged — code that reads or writes
// session.Subject / session.Issuer / session.ExpiresAt /
// session.IssuedAt continues to work.
type UserSession struct {
	Id                int    `json:"id"`
	Subject           string `json:"-"`
	Issuer            string `json:"-"`
	Email             string `json:"Email"`
	PartnerId         int64  `json:"PartnerId"`
	FirstName         string `json:"FirstName"`
	LastName          string `json:"LastName"`
	PhoneNumber       string `json:"PhoneNumber"`
	Language          string `json:"Language"`
	Status            string `json:"Status"`
	TwoFactorEnabled  bool   `json:"TwoFactorEnabled,omitempty"`
	TwoFactorMethod   string `json:"TwoFactorMethod,omitempty"`
	TwoFactorVerified bool   `json:"TwoFactorVerified,omitempty"`
	Provider          string
	ExpiresAt         int64 `json:"-"`
	IssuedAt          int64 `json:"-"`
	// NewRefreshToken is populated by ValidateRefreshToken when it
	// rotates the presented token. Clients must overwrite their
	// stored refresh-token value with this on every refresh response;
	// continuing to send the old token will fail (it has been revoked
	// in the same call that minted the new one). Empty in any session
	// not produced by a rotation path.
	NewRefreshToken string `json:"-"`
	jwt.RegisteredClaims
}

// SyncTimestamps populates the embedded jwt.RegisteredClaims from the
// in-Go mirror fields (Issuer, Subject, ExpiresAt, IssuedAt). jwt/v5's
// validator only inspects the embedded claims; without this sync,
// tokens issued by keel would be accepted indefinitely because the
// embedded ExpiresAt is nil. As of v0.4.3 the wire format ONLY
// carries the embedded claims (not the in-Go mirrors), so this
// method is also load-bearing for non-empty `iss` / `sub` on the
// emitted JWT.
func (s *UserSession) SyncTimestamps() {
	if s.ExpiresAt > 0 {
		s.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Unix(s.ExpiresAt, 0))
	}
	if s.IssuedAt > 0 {
		s.RegisteredClaims.IssuedAt = jwt.NewNumericDate(time.Unix(s.IssuedAt, 0))
	}
	if s.Issuer != "" {
		s.RegisteredClaims.Issuer = s.Issuer
	}
	if s.Subject != "" {
		s.RegisteredClaims.Subject = s.Subject
	}
}

// HydrateFromRegisteredClaims populates the in-Go mirror fields from
// the embedded RegisteredClaims after a successful parse. The wire
// format only carries the embedded claims (`iss`, `sub`, `exp`,
// `iat`), so anything reading session.Subject / session.Issuer /
// session.ExpiresAt / session.IssuedAt directly needs them mirrored
// back. service/user_service.go.ParseJWT calls this on the validated
// claims object before returning to the caller.
func (s *UserSession) HydrateFromRegisteredClaims() {
	if s.RegisteredClaims.ExpiresAt != nil {
		s.ExpiresAt = s.RegisteredClaims.ExpiresAt.Unix()
	}
	if s.RegisteredClaims.IssuedAt != nil {
		s.IssuedAt = s.RegisteredClaims.IssuedAt.Unix()
	}
	if s.Issuer == "" {
		s.Issuer = s.RegisteredClaims.Issuer
	}
	if s.Subject == "" {
		s.Subject = s.RegisteredClaims.Subject
	}
}

// GetToken returns a signed-ready *jwt.Token bound to HS256 with the
// embedded RegisteredClaims populated from the in-Go mirrors so jwt/v5's
// validator enforces expiry/iss/iat as expected.
func (s *UserSession) GetToken() *jwt.Token {
	s.SyncTimestamps()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, s)
}
