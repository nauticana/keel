package agency

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

const (
	rateQueryCatalog = "keel/agency/rate"
	qRateGet         = "agency_rate_get"
	qRateInsert      = "agency_rate_insert"
)

var rateQueries = map[string]string{
	qRateGet: `
SELECT commission_rate_bp
  FROM agency_client_rate
 WHERE agency_partner_id = ? AND client_partner_id = ?`,

	qRateInsert: `
INSERT INTO agency_client_rate
 (agency_partner_id, client_partner_id, commission_rate_bp)
SELECT ?, ?, r.commission_rate_bp
  FROM (
    SELECT COALESCE(p.default_commission_rate_bp, ?) AS commission_rate_bp
      FROM agency_profile p
     WHERE p.agency_partner_id = ?
  ) r
 WHERE r.commission_rate_bp > 0 AND r.commission_rate_bp <= 10000
ON CONFLICT (agency_partner_id, client_partner_id) DO NOTHING
RETURNING commission_rate_bp`,
}

// BaseFrozenRateResolver resolves an agency override or the program config
// once and freezes it in agency_client_rate. A concurrent loser re-reads the
// winning row; recognition never rewrites an existing rate.
type BaseFrozenRateResolver struct{}

func NewBaseFrozenRateResolver() *BaseFrozenRateResolver {
	return &BaseFrozenRateResolver{}
}

func (s *BaseFrozenRateResolver) Resolve(ctx context.Context, tx port.TxQueryService, agencyPartnerID, clientPartnerID int64) (int, error) {
	qs, err := transactionQueries(tx, rateQueryCatalog, rateQueries)
	if err != nil {
		return 0, err
	}
	row, err := queryFirst(ctx, qs, qRateGet, agencyPartnerID, clientPartnerID)
	if err != nil {
		return 0, fmt.Errorf("agency: read frozen client rate: %w", err)
	}
	if row != nil {
		return checkedRate(common.AsInt64(row[0]))
	}
	programRate := int64(common.Config().DefaultCommissionRateBP)
	row, err = queryFirst(ctx, qs, qRateInsert,
		agencyPartnerID, clientPartnerID, programRate, agencyPartnerID)
	if err != nil {
		return 0, fmt.Errorf("agency: freeze client rate: %w", err)
	}
	if row != nil {
		return checkedRate(common.AsInt64(row[0]))
	}
	row, err = queryFirst(ctx, qs, qRateGet, agencyPartnerID, clientPartnerID)
	if err != nil {
		return 0, fmt.Errorf("agency: re-read frozen client rate: %w", err)
	}
	if row == nil {
		return 0, port.ErrCommissionRateAbsent
	}
	return checkedRate(common.AsInt64(row[0]))
}

func checkedRate(rate int64) (int, error) {
	if rate <= 0 || rate > 10000 {
		return 0, port.ErrCommissionRateAbsent
	}
	return int(rate), nil
}

func transactionQueries(tx port.TxQueryService, catalogID string, queries map[string]string) (port.QueryService, error) {
	catalog, ok := tx.(port.TxQueryCatalog)
	if !ok {
		return nil, port.ErrTxQueryCatalog
	}
	return catalog.QueryService(catalogID, queries), nil
}

func queryFirst(ctx context.Context, qs port.QueryService, name string, args ...any) ([]any, error) {
	result, err := qs.Query(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, nil
	}
	return result.Rows[0], nil
}

var _ port.AgencyRateResolver = (*BaseFrozenRateResolver)(nil)
