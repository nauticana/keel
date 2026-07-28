package billing

import "time"

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

func (d *InvoiceDraft) TotalMinor() int64 {
	var t int64
	for _, l := range d.Lines {
		t += l.UnitPriceMinor * l.Quantity
	}
	return t
}
