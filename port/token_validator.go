package port

import "context"

// Principal is the validated identity carried by an OAuth 2.1 access token,
// produced by a resource-server TokenValidator.
type Principal struct {
	Subject  string
	Issuer   string
	Audience []string
	Scopes   []string
	Claims   map[string]any
}

// TokenValidator validates a bearer access token (resource-server role) and
// returns its principal, or an error if the token is missing/invalid/expired.
// Inject a concrete validator (e.g. service.JWTValidator) at composition time.
type TokenValidator interface {
	Validate(ctx context.Context, bearerToken string) (*Principal, error)
}
