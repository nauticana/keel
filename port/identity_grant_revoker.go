package port

import "context"

// IdentityGrantRevoker revokes a provider grant kept with an identity link,
// in the sealed form its adapter returned when the grant was redeemed.
type IdentityGrantRevoker interface {
	RevokeGrant(ctx context.Context, issuer, sealedGrant string) error
}
