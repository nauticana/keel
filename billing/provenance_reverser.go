package billing

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

type ReversalAllocation struct {
	OriginalAllocationID int64
	RefundAllocationID   int64
	PaymentRecordID      int64
	InvoiceID            int64
	InvoiceLineSequence  int
	OriginalAmountMinor  int64
	RefundedBeforeMinor  int64
	RefundAmountMinor    int64
	ProviderReference    string
}

type ReversalHook interface {
	ReverseAllocation(ctx context.Context, tx port.TxQueryService, reversal ReversalAllocation) error
}

type ReversalHookFunc func(context.Context, port.TxQueryService, ReversalAllocation) error

func (f ReversalHookFunc) ReverseAllocation(ctx context.Context, tx port.TxQueryService, reversal ReversalAllocation) error {
	return f(ctx, tx, reversal)
}

type PaymentProvenanceReverser interface {
	ReverseCumulativeByPayment(ctx context.Context, provider, providerPaymentID string, cumulativeRefundMinor int64, providerRef string) error
	ReverseCumulativeByCharge(ctx context.Context, provider, chargeID string, cumulativeRefundMinor int64, providerRef string) error
	ReverseIncrementalByCharge(ctx context.Context, provider, chargeID string, amountMinor int64, providerRef string) error
}

type BaseProvenanceReverser struct {
	DB       port.DatabaseRepository
	Reversal ReversalHook
}

func NewBaseProvenanceReverser(db port.DatabaseRepository, reversal ReversalHook) *BaseProvenanceReverser {
	return &BaseProvenanceReverser{DB: db, Reversal: reversal}
}

const (
	qReversalPaymentByRef    = "reversal_payment_by_ref"
	qReversalPaymentByCharge = "reversal_payment_by_charge"
	qReversalAllocations     = "reversal_allocations"
	qReversalRefundedTotal   = "reversal_refunded_total"
	qReversalInsert          = "reversal_insert"
)

var reversalQueries = map[string]string{
	qReversalPaymentByRef: `
SELECT id
  FROM payment_record
 WHERE provider = ? AND provider_payment_id = ?
 FOR UPDATE`,

	qReversalPaymentByCharge: `
SELECT id
  FROM payment_record
 WHERE provider = ? AND provider_charge_id = ?
 ORDER BY id
 LIMIT 1
 FOR UPDATE`,

	qReversalAllocations: `
SELECT p.id, p.invoice_id, p.invoice_line_seq, p.amount_minor,
       COALESCE((
         SELECT SUM(-r.amount_minor)
           FROM invoice_line_payment r
          WHERE r.payment_record_id = p.payment_record_id
            AND r.invoice_id = p.invoice_id
            AND r.invoice_line_seq = p.invoice_line_seq
            AND r.entry_type = 'R'
       ), 0)
  FROM invoice_line_payment p
 WHERE p.payment_record_id = ? AND p.entry_type = 'P'
 ORDER BY p.invoice_line_seq
 FOR UPDATE OF p`,

	qReversalRefundedTotal: `
SELECT COALESCE(SUM(-amount_minor), 0)
  FROM invoice_line_payment
 WHERE payment_record_id = ? AND entry_type = 'R'`,

	qReversalInsert: `
INSERT INTO invoice_line_payment
 (id, payment_record_id, invoice_id, invoice_line_seq,
  entry_type, amount_minor, provider_ref)
VALUES (?, ?, ?, ?, 'R', ?, ?)
ON CONFLICT (provider_ref) WHERE provider_ref IS NOT NULL DO NOTHING
RETURNING id`,
}

func (s *BaseProvenanceReverser) ReverseCumulativeByPayment(ctx context.Context, provider, providerPaymentID string, cumulativeRefundMinor int64, providerRef string) error {
	return s.reverse(ctx, qReversalPaymentByRef, provider, providerPaymentID, cumulativeRefundMinor, providerRef, true)
}

func (s *BaseProvenanceReverser) ReverseCumulativeByCharge(ctx context.Context, provider, chargeID string, cumulativeRefundMinor int64, providerRef string) error {
	return s.reverse(ctx, qReversalPaymentByCharge, provider, chargeID, cumulativeRefundMinor, providerRef, true)
}

func (s *BaseProvenanceReverser) ReverseIncrementalByCharge(ctx context.Context, provider, chargeID string, amountMinor int64, providerRef string) error {
	return s.reverse(ctx, qReversalPaymentByCharge, provider, chargeID, amountMinor, providerRef, false)
}

func (s *BaseProvenanceReverser) reverse(ctx context.Context, lookup, provider, identity string, amountMinor int64, providerRef string, cumulative bool) error {
	provider = strings.TrimSpace(provider)
	identity = strings.TrimSpace(identity)
	providerRef = strings.TrimSpace(providerRef)
	if provider == "" || identity == "" || amountMinor <= 0 || providerRef == "" {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, reversalQueries)
	if err != nil {
		return fmt.Errorf("billing: begin reversal transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()
	result, err := tx.Query(ctx, lookup, provider, identity)
	if err != nil {
		return fmt.Errorf("billing: find reversal payment: %w", err)
	}
	if len(result.Rows) == 0 {
		return fmt.Errorf("billing: reversal %s precedes payment %s/%s", providerRef, provider, identity)
	}
	paymentID := common.AsInt64(result.Rows[0][0])
	debit := amountMinor
	if cumulative {
		result, err = tx.Query(ctx, qReversalRefundedTotal, paymentID)
		if err != nil {
			return fmt.Errorf("billing: read refunded total: %w", err)
		}
		debit -= common.AsInt64(result.Rows[0][0])
	}
	if debit > 0 {
		if err = s.reversePayment(ctx, tx, paymentID, debit, providerRef); err != nil {
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("billing: commit reversal: %w", err)
	}
	committed = true
	return nil
}

type refundableAllocation struct {
	id        int64
	invoiceID int64
	sequence  int
	original  int64
	remaining int64
}

func (s *BaseProvenanceReverser) reversePayment(ctx context.Context, tx port.TxQueryService, paymentID, debitMinor int64, providerRef string) error {
	result, err := tx.Query(ctx, qReversalAllocations, paymentID)
	if err != nil {
		return fmt.Errorf("billing: lock payment allocations: %w", err)
	}
	allocations := make([]refundableAllocation, 0, len(result.Rows))
	var remainingTotal int64
	for _, row := range result.Rows {
		original := common.AsInt64(row[3])
		remaining := original - common.AsInt64(row[4])
		if original <= 0 || remaining <= 0 {
			continue
		}
		allocations = append(allocations, refundableAllocation{
			id:        common.AsInt64(row[0]),
			invoiceID: common.AsInt64(row[1]),
			sequence:  int(common.AsInt64(row[2])),
			original:  original,
			remaining: remaining,
		})
		remainingTotal += remaining
	}
	if debitMinor > remainingTotal {
		debitMinor = remainingTotal
	}
	if debitMinor <= 0 {
		return nil
	}
	debitLeft := debitMinor
	remainingPool := remainingTotal
	for index, allocation := range allocations {
		share := debitLeft
		if index < len(allocations)-1 {
			share, err = payment.MulDivFloor(debitLeft, allocation.remaining, remainingPool)
			if err != nil {
				return fmt.Errorf("billing: apportion reversal: %w", err)
			}
		}
		debitLeft -= share
		remainingPool -= allocation.remaining
		if share <= 0 {
			continue
		}
		ref := providerRef
		if len(allocations) > 1 {
			ref = fmt.Sprintf("%s#%d", providerRef, allocation.sequence)
		}
		result, err = tx.Query(ctx, qReversalInsert, tx.GenID(), paymentID,
			allocation.invoiceID, allocation.sequence, -share, ref)
		if err != nil {
			return fmt.Errorf("billing: insert refund allocation: %w", err)
		}
		if len(result.Rows) == 0 {
			continue
		}
		if s.Reversal != nil {
			if err = s.Reversal.ReverseAllocation(ctx, tx, ReversalAllocation{
				OriginalAllocationID: allocation.id,
				RefundAllocationID:   common.AsInt64(result.Rows[0][0]),
				PaymentRecordID:      paymentID,
				InvoiceID:            allocation.invoiceID,
				InvoiceLineSequence:  allocation.sequence,
				OriginalAmountMinor:  allocation.original,
				RefundedBeforeMinor:  allocation.original - allocation.remaining,
				RefundAmountMinor:    share,
				ProviderReference:    ref,
			}); err != nil {
				return fmt.Errorf("billing: reverse allocation %d: %w", allocation.id, err)
			}
		}
	}
	return nil
}

var _ ReversalHook = ReversalHookFunc(nil)
var _ PaymentProvenanceReverser = (*BaseProvenanceReverser)(nil)
