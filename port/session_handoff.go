package port

import (
	"context"
	"time"
)

// SessionHandoffStore persists authorization-server session hand-offs: a
// single-use code minted for a bearer-authenticated user, redeemed once on the
// AS host for a short-lived browser session. Only hashes are stored, and every
// expiry is judged by the store's clock.
type SessionHandoffStore interface {
	SaveHandoff(ctx context.Context, h *SessionHandoffCode, ttl time.Duration) error
	// RedeemHandoff atomically consumes the unexpired, unconsumed code bound to
	// returnURL and attaches sessionHash for sessionTTL; nil when none qualifies.
	RedeemHandoff(ctx context.Context, codeHash, returnURL, sessionHash string, sessionTTL time.Duration) (*UserRef, error)
	// ResolveHandoffSession returns the user of an unexpired session, else nil.
	ResolveHandoffSession(ctx context.Context, sessionHash string) (*UserRef, error)
	// EndHandoffSession expires a session; an unknown one is not an error.
	EndHandoffSession(ctx context.Context, sessionHash string) error
}

// SessionHandoffCode is a minted hand-off code awaiting redemption.
type SessionHandoffCode struct {
	CodeHash  string
	UserID    int64
	PartnerID int64
	ReturnURL string
}
