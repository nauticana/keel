package billing

import (
	"context"

	"github.com/nauticana/keel/payment"
)

// ProviderBillingStore is the provider-integration surface webhook hooks depend
// on: record provider invoices, map partner ↔ customer token, list methods.
// Split from BillingService (interface segregation).
type ProviderBillingStore interface {
	RecordProviderInvoice(ctx context.Context, partnerID int64, e *payment.PaymentEvent) error
	LinkCustomer(ctx context.Context, partnerID int64, provider, customerToken string) error
	CustomerToken(ctx context.Context, partnerID int64, provider string) (string, error)
	PartnerByCustomer(ctx context.Context, provider, customerToken string) (int64, error)
	ListPaymentMethods(ctx context.Context, partnerID int64) ([]PaymentMethodInfo, error)
}
