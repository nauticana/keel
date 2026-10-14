package billing

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/model"
)

// PartnerCustomerService resolves the provider customer of the partner a
// session acts for, so one partner keeps one customer across checkouts. Its
// methods back handler.AbstractPaymentHandler's CustomerID and LinkCustomer.
type PartnerCustomerService struct {
	Store    ProviderBillingStore
	Provider string // e.g. payment.ProviderStripe
}

// CustomerID returns the partner's provider customer, or "" when none is linked.
func (s *PartnerCustomerService) CustomerID(ctx context.Context, session *model.UserSession) (string, error) {
	partnerID, err := sessionPartner(session)
	if err != nil {
		return "", err
	}
	return s.Store.CustomerToken(ctx, partnerID, s.Provider)
}

// LinkCustomer keeps the first customer linked to the partner; later calls no-op.
func (s *PartnerCustomerService) LinkCustomer(ctx context.Context, session *model.UserSession, customerID string) error {
	partnerID, err := sessionPartner(session)
	if err != nil {
		return err
	}
	if customerID == "" {
		return fmt.Errorf("billing: LinkCustomer needs a customer id")
	}
	return s.Store.LinkCustomer(ctx, partnerID, s.Provider, customerID)
}

func sessionPartner(session *model.UserSession) (int64, error) {
	if session == nil || session.PartnerId <= 0 {
		return 0, fmt.Errorf("billing: no partner in session")
	}
	return session.PartnerId, nil
}
