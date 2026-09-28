package payout

import (
	"context"
	"fmt"
)

// StaticProviderResolver serves one deployment-wide provider to every partner.
type StaticProviderResolver struct {
	provider PayoutProvider
}

func NewStaticProviderResolver(provider PayoutProvider) *StaticProviderResolver {
	return &StaticProviderResolver{provider: provider}
}

func (r *StaticProviderResolver) ForPartner(_ context.Context, partnerID int64) (PayoutProvider, error) {
	if r.provider == nil {
		return nil, fmt.Errorf("%w: partner %d", ErrProviderNotConfigured, partnerID)
	}
	return r.provider, nil
}

func (r *StaticProviderResolver) ByCode(code string) (PayoutProvider, error) {
	if r.provider == nil || r.provider.Code() != code {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, code)
	}
	return r.provider, nil
}

var _ ProviderResolver = (*StaticProviderResolver)(nil)
