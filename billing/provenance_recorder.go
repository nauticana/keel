package billing

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

var (
	ErrIncompleteProviderInvoiceLines = errors.New("billing: incomplete provider invoice lines")
	ErrMissingInvoiceIdentity         = errors.New("billing: paid event is missing an invoice identity")
	ErrMissingPaymentIdentity         = errors.New("billing: paid event is missing a payment identity")
	ErrInvalidPaymentPartner          = errors.New("billing: paid event is missing a partner identity")
)

type ProvenanceAllocation struct {
	PaymentRecordID      int64
	InvoiceID            int64
	InvoiceLineSequence  int
	InvoiceLinePaymentID int64
	PartnerID            int64
	AmountMinor          int64
	Currency             string
	Line                 payment.InvoiceLine
}

type RecognitionHook interface {
	RecognizeAllocation(ctx context.Context, tx port.TxQueryService, allocation ProvenanceAllocation) error
}

type RecognitionHookFunc func(context.Context, port.TxQueryService, ProvenanceAllocation) error

func (f RecognitionHookFunc) RecognizeAllocation(ctx context.Context, tx port.TxQueryService, allocation ProvenanceAllocation) error {
	return f(ctx, tx, allocation)
}

type PaymentProvenanceRecorder interface {
	RecordPayment(ctx context.Context, partnerID int64, event *payment.PaymentEvent) error
}

type BaseProvenanceRecorderOptions struct {
	Recognition   RecognitionHook
	SyntheticLine func(event *payment.PaymentEvent) (*payment.InvoiceLine, error)
}

type BaseProvenanceRecorder struct {
	DB            port.DatabaseRepository
	Recognition   RecognitionHook
	SyntheticLine func(event *payment.PaymentEvent) (*payment.InvoiceLine, error)
}

func NewBaseProvenanceRecorder(db port.DatabaseRepository, opts BaseProvenanceRecorderOptions) *BaseProvenanceRecorder {
	return &BaseProvenanceRecorder{
		DB:            db,
		Recognition:   opts.Recognition,
		SyntheticLine: opts.SyntheticLine,
	}
}

const (
	qProvenanceInvoice          = "provenance_invoice"
	qProvenanceInsertPayment    = "provenance_insert_payment"
	qProvenanceInsertLine       = "provenance_insert_line"
	qProvenanceExistingLine     = "provenance_existing_line"
	qProvenanceInsertAllocation = "provenance_insert_allocation"
)

var provenanceQueries = map[string]string{
	qProvenanceInvoice: `
SELECT id, currency
  FROM invoice
 WHERE invoice_number = ? AND partner_id = ?
 LIMIT 1`,

	qProvenanceInsertPayment: `
INSERT INTO payment_record
 (id, partner_id, provider, provider_payment_id, provider_event_type,
  provider_charge_id, amount, amount_minor, currency, invoice_id,
  payment_status, paid_at, raw_payload)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'P', ?, ?)
ON CONFLICT (provider, provider_payment_id)
  WHERE provider_payment_id IS NOT NULL DO NOTHING
RETURNING id`,

	qProvenanceInsertLine: `
INSERT INTO invoice_line
 (invoice_id, seq, description, quantity, unit_price, amount,
  amount_minor, service_from, service_to)
VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
ON CONFLICT (invoice_id, seq) DO NOTHING
RETURNING invoice_id`,

	qProvenanceExistingLine: `
SELECT description, amount_minor, service_from, service_to
  FROM invoice_line
 WHERE invoice_id = ? AND seq = ?`,

	qProvenanceInsertAllocation: `
INSERT INTO invoice_line_payment
 (id, payment_record_id, invoice_id, invoice_line_seq, entry_type, amount_minor)
VALUES (?, ?, ?, ?, 'P', ?)
RETURNING id`,
}

func (s *BaseProvenanceRecorder) RecordPayment(ctx context.Context, partnerID int64, event *payment.PaymentEvent) error {
	if event == nil || event.MinorUnits <= 0 {
		return nil
	}
	if partnerID <= 0 {
		return ErrInvalidPaymentPartner
	}
	if strings.TrimSpace(event.InvoiceID) == "" {
		return ErrMissingInvoiceIdentity
	}
	providerPaymentID := paymentIdentity(event)
	if providerPaymentID == "" {
		return ErrMissingPaymentIdentity
	}
	currency := strings.ToUpper(strings.TrimSpace(event.Currency))
	if len(currency) != 3 {
		return fmt.Errorf("billing: invalid payment currency %q", event.Currency)
	}
	lines, err := s.validatedLines(event, currency)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, provenanceQueries)
	if err != nil {
		return fmt.Errorf("billing: begin provenance transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = port.RollbackDetached(tx)
		}
	}()

	invoice, err := tx.Query(ctx, qProvenanceInvoice, event.InvoiceID, partnerID)
	if err != nil {
		return fmt.Errorf("billing: find invoice %s: %w", event.InvoiceID, err)
	}
	if len(invoice.Rows) == 0 {
		return fmt.Errorf("billing: invoice %s is not recorded for partner %d", event.InvoiceID, partnerID)
	}
	invoiceID := common.AsInt64(invoice.Rows[0][0])
	if !strings.EqualFold(common.AsString(invoice.Rows[0][1]), currency) {
		return fmt.Errorf("billing: payment currency %s differs from invoice currency %s", currency, common.AsString(invoice.Rows[0][1]))
	}
	paymentID := tx.GenID()
	inserted, err := tx.Query(ctx, qProvenanceInsertPayment,
		paymentID, partnerID, event.Provider, providerPaymentID, event.EventType,
		event.ChargeID, payment.MinorToMajor(event.MinorUnits, currency),
		event.MinorUnits, currency, invoiceID, event.PaidAt, event.RawPayload)
	if err != nil {
		return fmt.Errorf("billing: insert payment provenance: %w", err)
	}
	if len(inserted.Rows) == 0 {
		// A committed duplicate already includes its lines, allocations, and
		// recognition hook because all of them share this transaction.
		if err = tx.Commit(ctx); err != nil {
			return fmt.Errorf("billing: commit provenance replay: %w", err)
		}
		committed = true
		return nil
	}
	paymentID = common.AsInt64(inserted.Rows[0][0])
	amounts, err := apportionLineAmounts(event.MinorUnits, lines)
	if err != nil {
		return err
	}
	for index, line := range lines {
		sequence := index + 1
		amountMinor := amounts[index]
		major := payment.MinorToMajor(line.AmountMinor, currency)
		result, insertErr := tx.Query(ctx, qProvenanceInsertLine,
			invoiceID, sequence, line.Description, major, major,
			line.AmountMinor, line.ServiceFrom, line.ServiceTo)
		if insertErr != nil {
			return fmt.Errorf("billing: insert invoice line %d: %w", sequence, insertErr)
		}
		if len(result.Rows) == 0 {
			if err = validateExistingInvoiceLine(ctx, tx, invoiceID, sequence, line, line.AmountMinor); err != nil {
				return err
			}
		}
		if amountMinor <= 0 {
			continue
		}
		allocationID := tx.GenID()
		result, err = tx.Query(ctx, qProvenanceInsertAllocation,
			allocationID, paymentID, invoiceID, sequence, amountMinor)
		if err != nil {
			return fmt.Errorf("billing: insert line allocation %d: %w", sequence, err)
		}
		if len(result.Rows) == 0 {
			return fmt.Errorf("billing: insert line allocation %d returned no id", sequence)
		}
		allocationID = common.AsInt64(result.Rows[0][0])
		if s.Recognition != nil {
			if err = s.Recognition.RecognizeAllocation(ctx, tx, ProvenanceAllocation{
				PaymentRecordID:      paymentID,
				InvoiceID:            invoiceID,
				InvoiceLineSequence:  sequence,
				InvoiceLinePaymentID: allocationID,
				PartnerID:            partnerID,
				AmountMinor:          amountMinor,
				Currency:             currency,
				Line:                 line,
			}); err != nil {
				return fmt.Errorf("billing: recognize allocation %d: %w", allocationID, err)
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("billing: commit provenance: %w", err)
	}
	committed = true
	return nil
}

func (s *BaseProvenanceRecorder) validatedLines(event *payment.PaymentEvent, currency string) ([]payment.InvoiceLine, error) {
	lines := append([]payment.InvoiceLine(nil), event.InvoiceLines...)
	if !event.InvoiceLinesComplete {
		if s.SyntheticLine == nil {
			return nil, fmt.Errorf("%w: provider %s did not supply a complete line list", ErrIncompleteProviderInvoiceLines, event.Provider)
		}
		line, err := s.SyntheticLine(event)
		if err != nil {
			return nil, err
		}
		if line == nil {
			return nil, fmt.Errorf("%w: synthetic line policy declined the event", ErrIncompleteProviderInvoiceLines)
		}
		lines = []payment.InvoiceLine{*line}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("%w: provider supplied an empty line list", ErrIncompleteProviderInvoiceLines)
	}
	hasPositiveLine := false
	for index := range lines {
		line := &lines[index]
		line.Description = truncateRunes(line.Description, 200)
		if !line.ServiceTo.After(line.ServiceFrom) {
			return nil, fmt.Errorf("%w: line %q has an invalid period", ErrIncompleteProviderInvoiceLines, line.ProviderLineID)
		}
		if !strings.EqualFold(strings.TrimSpace(line.Currency), currency) {
			return nil, fmt.Errorf("%w: line %q currency %q differs from %q", ErrIncompleteProviderInvoiceLines, line.ProviderLineID, line.Currency, currency)
		}
		if line.AmountMinor > 0 {
			hasPositiveLine = true
		}
	}
	if !hasPositiveLine {
		return nil, fmt.Errorf("%w: provider supplied no positive service line", ErrIncompleteProviderInvoiceLines)
	}
	return lines, nil
}

func apportionLineAmounts(total int64, lines []payment.InvoiceLine) ([]int64, error) {
	var positiveTotal int64
	positiveIndexes := make([]int, 0, len(lines))
	for index, line := range lines {
		if line.AmountMinor <= 0 {
			continue
		}
		if positiveTotal > math.MaxInt64-line.AmountMinor {
			return nil, payment.ErrMoneyArithmetic
		}
		positiveTotal += line.AmountMinor
		positiveIndexes = append(positiveIndexes, index)
	}
	if total <= 0 || positiveTotal <= 0 {
		return nil, payment.ErrMoneyArithmetic
	}
	amounts := make([]int64, len(lines))
	var assigned int64
	for position, index := range positiveIndexes {
		if position == len(positiveIndexes)-1 {
			amounts[index] = total - assigned
		} else {
			amount, err := payment.MulDivFloor(total, lines[index].AmountMinor, positiveTotal)
			if err != nil {
				return nil, fmt.Errorf("billing: apportion invoice lines: %w", err)
			}
			amounts[index] = amount
			assigned += amount
		}
	}
	return amounts, nil
}

func paymentIdentity(event *payment.PaymentEvent) string {
	for _, identity := range []string{event.PaymentID, event.ChargeID, event.ProviderEventID} {
		if identity = strings.TrimSpace(identity); identity != "" {
			return identity
		}
	}
	return ""
}

func truncateRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func validateExistingInvoiceLine(ctx context.Context, tx port.TxQueryService, invoiceID int64, sequence int, expected payment.InvoiceLine, expectedAmount int64) error {
	result, err := tx.Query(ctx, qProvenanceExistingLine, invoiceID, sequence)
	if err != nil {
		return fmt.Errorf("billing: read existing invoice line %d: %w", sequence, err)
	}
	if len(result.Rows) == 0 {
		return fmt.Errorf("billing: invoice line %d conflicted but cannot be read", sequence)
	}
	row := result.Rows[0]
	if common.AsString(row[0]) != expected.Description || common.AsInt64(row[1]) != expectedAmount ||
		!common.AsTime(row[2]).Equal(expected.ServiceFrom) || !common.AsTime(row[3]).Equal(expected.ServiceTo) {
		return fmt.Errorf("billing: existing invoice line %d does not match provider provenance", sequence)
	}
	return nil
}

var _ RecognitionHook = RecognitionHookFunc(nil)
var _ PaymentProvenanceRecorder = (*BaseProvenanceRecorder)(nil)
