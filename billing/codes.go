package billing

// invoice.status codes (constant invoice_status).
const (
	InvoiceStatusDraft          = "D"
	InvoiceStatusOpen           = "O" // self-scheduled, awaiting a charge
	InvoiceStatusActionRequired = "A" // the charge needs customer action
	InvoiceStatusPaid           = "P"
	InvoiceStatusVoid           = "V"
)

// payment_record.payment_status codes (constant payment_status).
const (
	PaymentStatusPaid     = "P"
	PaymentStatusFailed   = "F"
	PaymentStatusRefunded = "R"
)
