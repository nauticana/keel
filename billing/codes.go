package billing

// invoice.status codes (constant invoice_status).
const (
	InvoiceStatusDraft          = "D"
	InvoiceStatusOpen           = "O" // self-scheduled, awaiting a charge
	InvoiceStatusActionRequired = "A" // the charge needs customer action
	InvoiceStatusSettling       = "S" // the charge is accepted and settles later
	InvoiceStatusPaid           = "P"
	InvoiceStatusVoid           = "V"
)

// payment_record.payment_status codes (constant payment_status).
const (
	PaymentStatusPaid     = "P"
	PaymentStatusFailed   = "F"
	PaymentStatusRefunded = "R"
)

// partner_plan_subscription.status codes (constant subscription_status).
const (
	SubscriptionStatusActive    = "A"
	SubscriptionStatusPending   = "P" // awaiting payment or an administrator's activation
	SubscriptionStatusTrialing  = "T"
	SubscriptionStatusCancelled = "C"
	SubscriptionStatusPastDue   = "X" // expired or past due
)
