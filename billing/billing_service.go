package billing

import "context"

// BillingService is the read/write contract every consumer's billing HTTP
// handler depends on. AbstractBillingService is the default impl; a project
// embeds it and overrides only what differs.
type BillingService interface {
	GetSubscription(ctx context.Context, partnerID int64) (*Subscription, error)
	CreateSubscription(ctx context.Context, partnerID int64, planID string, terms BillingTerms) error
	CancelSubscription(ctx context.Context, partnerID int64) error
	GetInvoices(ctx context.Context, partnerID int64) ([]Invoice, error)
	GetUsage(ctx context.Context, partnerID int64) ([]UsageItem, error)
	GetPlans(ctx context.Context) ([]Plan, error)
}
