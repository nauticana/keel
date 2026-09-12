package port

import (
	"context"

	"github.com/nauticana/keel/model"
)

// TokenValidator validates a bearer access token (resource-server role) and
// returns its principal, or an error if the token is missing/invalid/expired.
// Inject a concrete validator (e.g. oauth/resource.JWTValidator) at composition time.
type TokenValidator interface {
	Validate(ctx context.Context, bearerToken string) (*model.TokenPrincipal, error)
}
