package service

import (
	"context"

	"github.com/nauticana/keel/payment"
)

// ProviderBillingStore is the provider-integration surface beyond the core
// subscription CRUD: it records provider-issued invoices, maps a partner to its
// provider-customer token, and lists saved methods. Webhook hooks and billing
// bridges depend on THIS interface (not the concrete *AbstractBillingService),
// so any keel consumer can substitute its own implementation. Kept separate
// from BillingService so a project needing only the read/write CRUD surface
// isn't forced to implement the webhook-write methods (interface segregation).
type ProviderBillingStore interface {
	RecordProviderInvoice(ctx context.Context, partnerID int64, e *payment.PaymentEvent) error
	LinkCustomer(ctx context.Context, partnerID int64, provider, customerToken string) error
	CustomerToken(ctx context.Context, partnerID int64, provider string) (string, error)
	PartnerByCustomer(ctx context.Context, provider, customerToken string) (int64, error)
	ListPaymentMethods(ctx context.Context, partnerID int64) ([]PaymentMethodInfo, error)
}
