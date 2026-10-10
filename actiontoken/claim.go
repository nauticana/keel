package actiontoken

import "github.com/nauticana/keel/port"

const (
	maxAction      = 100
	maxResourceKey = 200
	maxDigest      = 128
)

// Binding is what a token authorizes: one action on one resource at one content
// digest. A redemption presenting any other binding is refused.
type Binding struct {
	Action      string
	ResourceKey string
	Digest      string
}

func (b Binding) valid() bool {
	return b.Action != "" && len(b.Action) <= maxAction &&
		b.ResourceKey != "" && len(b.ResourceKey) <= maxResourceKey &&
		b.Digest != "" && len(b.Digest) <= maxDigest
}

// Claim is a redeemed token: ID keys its idempotency ledger entry, and User is
// the principal the token was minted for.
type Claim struct {
	ID   int64
	User port.UserRef
	Binding
}
