package payout

import (
	"context"
	"fmt"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

const qPartnerPayoutProvider = "payout_partner_provider"

var providerResolverQueries = map[string]string{
	qPartnerPayoutProvider: `
SELECT provider FROM partner_payout_provider WHERE partner_id = ?`,
}

// SQLProviderResolver picks each partner's provider from its
// partner_payout_provider row among the providers configured at boot.
// A partner without a row has no provider; there is no implicit fallback.
type SQLProviderResolver struct {
	DB        port.DatabaseRepository
	providers map[string]PayoutProvider

	qsOnce sync.Once
	qs     port.QueryService
}

func NewSQLProviderResolver(db port.DatabaseRepository, providers ...PayoutProvider) *SQLProviderResolver {
	byCode := make(map[string]PayoutProvider, len(providers))
	for _, p := range providers {
		byCode[p.Code()] = p
	}
	return &SQLProviderResolver{DB: db, providers: byCode}
}

func (r *SQLProviderResolver) queryService(ctx context.Context) port.QueryService {
	r.qsOnce.Do(func() {
		r.qs = r.DB.GetQueryService(ctx, providerResolverQueries)
	})
	return r.qs
}

func (r *SQLProviderResolver) ForPartner(ctx context.Context, partnerID int64) (PayoutProvider, error) {
	res, err := r.queryService(ctx).Query(ctx, qPartnerPayoutProvider, partnerID)
	if err != nil {
		return nil, fmt.Errorf("resolve payout provider for partner %d: %w", partnerID, err)
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("%w: partner %d", ErrProviderNotConfigured, partnerID)
	}
	return r.ByCode(common.AsString(res.Rows[0][0]))
}

func (r *SQLProviderResolver) ByCode(code string) (PayoutProvider, error) {
	p, ok := r.providers[code]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, code)
	}
	return p, nil
}

var _ ProviderResolver = (*SQLProviderResolver)(nil)
