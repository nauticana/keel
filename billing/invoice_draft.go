package billing

import (
	"errors"
	"math"
	"time"
)

// ErrInvoiceAmountOverflow: a line amount or the invoice total does not fit int64 minor units.
var ErrInvoiceAmountOverflow = errors.New("billing: invoice amount overflows int64 minor units")

// InvoiceLineDraft / InvoiceDraft describe the period invoice a project computes
// for a partner. Amounts are minor currency units (e.g. cents).
// ServiceFrom / ServiceTo (inclusive / exclusive) bound the covered-service
// period. PlanID / AddonID, when set, produce a subscription_invoice_line
// extension row — the generic invoice_line itself stays domain-neutral.
type InvoiceLineDraft struct {
	Description    string
	Quantity       int64
	UnitPriceMinor int64
	ServiceFrom    time.Time
	ServiceTo      time.Time
	PlanID         string
	AddonID        string
}

type InvoiceDraft struct {
	Currency string
	Lines    []InvoiceLineDraft
}

// TotalMinor sums the line amounts; ErrInvoiceAmountOverflow when they do not fit int64.
func (d *InvoiceDraft) TotalMinor() (int64, error) {
	_, total, err := d.amounts()
	return total, err
}

func (d *InvoiceDraft) amounts() ([]int64, int64, error) {
	lines := make([]int64, len(d.Lines))
	var total int64
	for i, l := range d.Lines {
		amount := l.UnitPriceMinor * l.Quantity
		if l.Quantity != 0 && (amount/l.Quantity != l.UnitPriceMinor || l.Quantity == -1 && l.UnitPriceMinor == math.MinInt64) {
			return nil, 0, ErrInvoiceAmountOverflow
		}
		if amount > 0 && total > math.MaxInt64-amount || amount < 0 && total < math.MinInt64-amount {
			return nil, 0, ErrInvoiceAmountOverflow
		}
		total += amount
		lines[i] = amount
	}
	return lines, total, nil
}
