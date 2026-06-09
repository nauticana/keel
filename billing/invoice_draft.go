package billing

// InvoiceLineDraft / InvoiceDraft describe the period invoice a project computes
// for a partner. Amounts are minor currency units (e.g. cents).
type InvoiceLineDraft struct {
	Description    string
	Quantity       int64
	UnitPriceMinor int64
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
