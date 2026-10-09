package client

import "context"

// Initiator is the signed-in user and partner who start or finish a connect
// flow. The state binds to it, so a consent completed in another person's
// browser cannot land in the initiator's tenant (RFC 6749 §10.12).
type Initiator struct {
	UserID    int64
	PartnerID int64
}

type initiatorKey struct{}

func WithInitiator(ctx context.Context, i Initiator) context.Context {
	return context.WithValue(ctx, initiatorKey{}, i)
}

func InitiatorFrom(ctx context.Context) (Initiator, bool) {
	i, ok := ctx.Value(initiatorKey{}).(Initiator)
	return i, ok && i.UserID > 0 && i.PartnerID > 0
}
