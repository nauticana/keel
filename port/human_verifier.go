package port

import (
	"context"
	"errors"
)

// HumanVerifier decides whether a challenge token issued to a browser proves a
// person made the request. A refusal is one of the sentinels below.
type HumanVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

var (
	// ErrChallengeRequired: the request carried no challenge token.
	ErrChallengeRequired = errors.New("human: challenge token is required")
	// ErrChallengeFailed: the provider rejected the token.
	ErrChallengeFailed = errors.New("human: challenge failed")
	// ErrChallengeUnavailable: the provider could not be asked; the check fails closed.
	ErrChallengeUnavailable = errors.New("human: challenge verification unavailable")
)
