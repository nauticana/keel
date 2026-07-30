package agency

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

const (
	commissionQueryCatalog = "keel/agency/commission"
	qCommissionDelegations = "agency_commission_delegations"
	qCommissionModels      = "agency_commission_models"
	qCommissionInsert      = "agency_commission_insert"
)

var commissionQueries = map[string]string{
	qCommissionDelegations: `
SELECT d.id, d.agency_partner_id, d.granted_at, d.revoked_at
  FROM agency_client_delegation d
  JOIN agency_profile p ON p.agency_partner_id = d.agency_partner_id
 WHERE d.client_partner_id = ?
   AND p.approved_at IS NOT NULL AND p.suspended = FALSE
   AND d.granted_at < ?
   AND (d.revoked_at IS NULL OR d.revoked_at > ?)
 ORDER BY d.granted_at`,

	qCommissionModels: `
SELECT id, billing_model, effective_from, effective_to
  FROM agency_client_billing
 WHERE client_delegation_id = ?
   AND effective_from < ?
   AND (effective_to IS NULL OR effective_to > ?)
 ORDER BY effective_from`,

	qCommissionInsert: `
INSERT INTO agency_commission
 (id, client_billing_id, invoice_line_payment_id,
  earning_period_start, earning_period_end, gross_amount_minor,
  commission_amount_minor, applied_rate_bp, currency, entry_type, status, earned_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'E', 'H', ?)
ON CONFLICT (invoice_line_payment_id, earning_period_start)
  WHERE entry_type = 'E' DO NOTHING`,
}

type BaseCommissionRecognizer struct {
	Rates port.AgencyRateResolver
}

func NewBaseCommissionRecognizer(rates port.AgencyRateResolver) *BaseCommissionRecognizer {
	if rates == nil {
		rates = NewBaseFrozenRateResolver()
	}
	return &BaseCommissionRecognizer{Rates: rates}
}

func (s *BaseCommissionRecognizer) Recognize(ctx context.Context, tx port.TxQueryService, source port.AgencyCommissionSource) error {
	source.Currency = strings.ToUpper(strings.TrimSpace(source.Currency))
	if source.InvoiceLinePaymentID <= 0 || source.ClientPartnerID <= 0 ||
		source.GrossAmountMinor <= 0 || len(source.Currency) != 3 ||
		!source.PeriodEnd.After(source.PeriodStart) {
		return port.ErrInvalidCommission
	}
	if source.EarnedAt.IsZero() {
		source.EarnedAt = time.Now().UTC()
	}
	qs, err := transactionQueries(tx, commissionQueryCatalog, commissionQueries)
	if err != nil {
		return err
	}
	result, err := qs.Query(ctx, qCommissionDelegations,
		source.ClientPartnerID, source.PeriodEnd, source.PeriodStart)
	if err != nil {
		return fmt.Errorf("agency: resolve delegations: %w", err)
	}
	if len(result.Rows) == 0 {
		return nil
	}

	delegations := make([]commissionDelegation, 0, len(result.Rows))
	boundaries := make([]time.Time, 0, len(result.Rows)*2)
	for _, row := range result.Rows {
		delegation := commissionDelegation{
			id:       common.AsInt64(row[0]),
			agencyID: common.AsInt64(row[1]),
			from:     common.AsTime(row[2]),
			to:       common.AsTime(row[3]),
		}
		delegations = append(delegations, delegation)
		boundaries = append(boundaries, delegation.from, delegation.to)
	}

	models := make(map[int64][]commissionModel, len(delegations))
	for _, delegation := range delegations {
		result, err = qs.Query(ctx, qCommissionModels,
			delegation.id, source.PeriodEnd, source.PeriodStart)
		if err != nil {
			return fmt.Errorf("agency: resolve billing models: %w", err)
		}
		for _, row := range result.Rows {
			model := commissionModel{
				id:    common.AsInt64(row[0]),
				model: common.AsString(row[1]),
				from:  common.AsTime(row[2]),
				to:    common.AsTime(row[3]),
			}
			models[delegation.id] = append(models[delegation.id], model)
			boundaries = append(boundaries, model.from, model.to)
		}
	}

	spans := cutCommissionSpans(boundaries, source.PeriodStart, source.PeriodEnd)
	periodNanos := int64(source.PeriodEnd.Sub(source.PeriodStart))
	var apportioned int64
	rates := map[int64]int{}
	for i, span := range spans {
		gross := source.GrossAmountMinor - apportioned
		if i < len(spans)-1 {
			gross, err = payment.MulDivFloor(
				source.GrossAmountMinor, int64(span.to.Sub(span.from)), periodNanos)
			if err != nil {
				return fmt.Errorf("agency: apportion commission gross: %w", err)
			}
		}
		apportioned += gross
		delegation, ok := commissionDelegationAt(delegations, span.from)
		if !ok {
			continue
		}
		model, ok := commissionModelAt(models[delegation.id], span.from)
		if !ok || model.model != "R" {
			continue
		}
		rate, ok := rates[delegation.agencyID]
		if !ok {
			rate, err = s.Rates.Resolve(ctx, tx, delegation.agencyID, source.ClientPartnerID)
			if err != nil {
				return err
			}
			rates[delegation.agencyID] = rate
		}
		amount, err := payment.MulDivRoundHalfEven(gross, int64(rate), 10000)
		if err != nil {
			return fmt.Errorf("agency: calculate commission: %w", err)
		}
		if amount <= 0 {
			continue
		}
		if _, err = qs.Query(ctx, qCommissionInsert,
			tx.GenID(), model.id, source.InvoiceLinePaymentID,
			span.from, span.to, gross, amount, rate, source.Currency, source.EarnedAt); err != nil {
			return fmt.Errorf("agency: insert commission earning: %w", err)
		}
	}
	return nil
}

type commissionDelegation struct {
	id       int64
	agencyID int64
	from     time.Time
	to       time.Time
}

type commissionModel struct {
	id    int64
	model string
	from  time.Time
	to    time.Time
}

type commissionSpan struct {
	from time.Time
	to   time.Time
}

func cutCommissionSpans(boundaries []time.Time, start, end time.Time) []commissionSpan {
	cuts := []time.Time{start, end}
	for _, boundary := range boundaries {
		if !boundary.IsZero() && boundary.After(start) && boundary.Before(end) {
			cuts = append(cuts, boundary)
		}
	}
	sort.Slice(cuts, func(i, j int) bool { return cuts[i].Before(cuts[j]) })
	spans := make([]commissionSpan, 0, len(cuts)-1)
	for i := 0; i < len(cuts)-1; i++ {
		if cuts[i+1].After(cuts[i]) {
			spans = append(spans, commissionSpan{from: cuts[i], to: cuts[i+1]})
		}
	}
	return spans
}

func commissionDelegationAt(delegations []commissionDelegation, at time.Time) (commissionDelegation, bool) {
	for _, delegation := range delegations {
		if !delegation.from.After(at) && (delegation.to.IsZero() || delegation.to.After(at)) {
			return delegation, true
		}
	}
	return commissionDelegation{}, false
}

func commissionModelAt(models []commissionModel, at time.Time) (commissionModel, bool) {
	for _, model := range models {
		if !model.from.After(at) && (model.to.IsZero() || model.to.After(at)) {
			return model, true
		}
	}
	return commissionModel{}, false
}

var _ port.AgencyCommissionRecognizer = (*BaseCommissionRecognizer)(nil)
