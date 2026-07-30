package agency

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

const (
	commissionReversalQueryCatalog = "keel/agency/reversal"
	qReversalEarnings              = "agency_reversal_earnings"
	qReversalAmountSum             = "agency_reversal_amount_sum"
	qReversalGrossSum              = "agency_reversal_gross_sum"
	qReversalInsert                = "agency_reversal_insert"
	qReversalOffsetFamily          = "agency_reversal_offset_family"
)

var commissionReversalQueries = map[string]string{
	qReversalEarnings: `
SELECT id, client_billing_id, earning_period_start, earning_period_end,
       gross_amount_minor, commission_amount_minor, applied_rate_bp,
       currency, status
  FROM agency_commission
 WHERE invoice_line_payment_id = ? AND entry_type = 'E'
 ORDER BY earning_period_start
 FOR UPDATE`,

	qReversalAmountSum: `
SELECT COALESCE(SUM(-commission_amount_minor), 0)
  FROM agency_commission
 WHERE reversal_of_id = ?`,

	qReversalGrossSum: `
SELECT COALESCE(SUM(-gross_amount_minor), 0)
  FROM agency_commission
 WHERE reversal_of_id = ?`,

	qReversalInsert: `
INSERT INTO agency_commission
 (id, client_billing_id, invoice_line_payment_id,
  earning_period_start, earning_period_end, gross_amount_minor,
  commission_amount_minor, applied_rate_bp, currency, entry_type, status,
  reversal_of_id, earned_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'R', ?, ?, CURRENT_TIMESTAMP)`,

	qReversalOffsetFamily: `
UPDATE agency_commission
   SET status = 'O'
 WHERE (id = ? OR reversal_of_id = ?) AND status IN ('H', 'P')`,
}

// BaseCommissionReverser translates a provenance refund allocation into
// append-only negative commission entries. Refunds are apportioned against
// the full paid allocation, so wholesale/ineligible time is never redirected
// into the referral segments that happened to earn.
type BaseCommissionReverser struct{}

func NewBaseCommissionReverser() *BaseCommissionReverser {
	return &BaseCommissionReverser{}
}

func (s *BaseCommissionReverser) ReverseAllocation(ctx context.Context, tx port.TxQueryService, reversal billing.ReversalAllocation) error {
	if reversal.OriginalAllocationID <= 0 || reversal.RefundAllocationID <= 0 ||
		reversal.OriginalAmountMinor <= 0 || reversal.RefundAmountMinor <= 0 {
		return port.ErrInvalidCommission
	}
	qs, err := transactionQueries(tx, commissionReversalQueryCatalog, commissionReversalQueries)
	if err != nil {
		return err
	}
	result, err := qs.Query(ctx, qReversalEarnings, reversal.OriginalAllocationID)
	if err != nil {
		return fmt.Errorf("agency: lock earnings for reversal: %w", err)
	}
	for _, row := range result.Rows {
		originalID := common.AsInt64(row[0])
		originalGross := common.AsInt64(row[4])
		originalAmount := common.AsInt64(row[5])
		originalStatus := common.AsString(row[8])

		amountSum, queryErr := queryFirst(ctx, qs, qReversalAmountSum, originalID)
		if queryErr != nil {
			return fmt.Errorf("agency: sum prior commission reversals: %w", queryErr)
		}
		amountRemaining := originalAmount
		if amountSum != nil {
			amountRemaining -= common.AsInt64(amountSum[0])
		}
		grossSum, queryErr := queryFirst(ctx, qs, qReversalGrossSum, originalID)
		if queryErr != nil {
			return fmt.Errorf("agency: sum prior gross reversals: %w", queryErr)
		}
		grossRemaining := originalGross
		if grossSum != nil {
			grossRemaining -= common.AsInt64(grossSum[0])
		}
		amountShare, calcErr := cumulativeReversalShare(
			originalAmount, originalAmount-amountRemaining,
			reversal.RefundedBeforeMinor, reversal.RefundAmountMinor,
			reversal.OriginalAmountMinor)
		if calcErr != nil {
			return fmt.Errorf("agency: calculate commission reversal: %w", calcErr)
		}
		grossShare, calcErr := cumulativeReversalShare(
			originalGross, originalGross-grossRemaining,
			reversal.RefundedBeforeMinor, reversal.RefundAmountMinor,
			reversal.OriginalAmountMinor)
		if calcErr != nil {
			return fmt.Errorf("agency: calculate gross reversal: %w", calcErr)
		}
		if amountShare > amountRemaining {
			amountShare = amountRemaining
		}
		if grossShare > grossRemaining {
			grossShare = grossRemaining
		}
		if amountShare <= 0 || grossShare <= 0 {
			continue
		}
		fullyConsumed := amountShare == amountRemaining && grossShare == grossRemaining
		status := "P"
		if fullyConsumed && (originalStatus == "H" || originalStatus == "P") {
			status = "O"
		}
		if _, err = qs.Query(ctx, qReversalInsert,
			tx.GenID(), common.AsInt64(row[1]), reversal.RefundAllocationID,
			common.AsTime(row[2]), common.AsTime(row[3]), -grossShare, -amountShare,
			common.AsInt64(row[6]), common.AsString(row[7]), status, originalID); err != nil {
			return fmt.Errorf("agency: insert commission reversal: %w", err)
		}
		if fullyConsumed && (originalStatus == "H" || originalStatus == "P") {
			if _, err = qs.Query(ctx, qReversalOffsetFamily, originalID, originalID); err != nil {
				return fmt.Errorf("agency: offset commission family: %w", err)
			}
		}
	}
	return nil
}

func cumulativeReversalShare(original, alreadyReversed, refundedBefore, refund, originalPayment int64) (int64, error) {
	if original <= 0 || alreadyReversed < 0 || alreadyReversed > original ||
		refundedBefore < 0 || refund <= 0 || originalPayment <= 0 ||
		refundedBefore > originalPayment || refund > originalPayment-refundedBefore {
		return 0, payment.ErrMoneyArithmetic
	}
	target, err := payment.MulDivRoundHalfEven(
		original, refundedBefore+refund, originalPayment)
	if err != nil {
		return 0, err
	}
	share := target - alreadyReversed
	if share < 0 {
		return 0, payment.ErrMoneyArithmetic
	}
	if remaining := original - alreadyReversed; share > remaining {
		share = remaining
	}
	return share, nil
}

var _ billing.ReversalHook = (*BaseCommissionReverser)(nil)
