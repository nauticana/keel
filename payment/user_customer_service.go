package payment

import (
	"context"
	"fmt"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

const (
	qUserCustomerToken = "user_customer_token"
	qUserCustomerLink  = "user_customer_link"
)

var userCustomerQueries = map[string]string{
	qUserCustomerToken: `
SELECT customer_token FROM user_billing_customer
 WHERE user_id = ? AND provider = ?`,

	qUserCustomerLink: `
INSERT INTO user_billing_customer (user_id, provider, customer_token)
VALUES (?, ?, ?)
ON CONFLICT (user_id, provider) DO NOTHING`,
}

// UserCustomerService stores the provider customer of a user who pays for
// themselves. CustomerID and LinkCustomer back the same-named hooks on
// handler.AbstractPaymentHandler.
type UserCustomerService struct {
	DB       port.DatabaseRepository
	Provider string

	once sync.Once
	qs   port.QueryService
}

func (s *UserCustomerService) queries(ctx context.Context) (port.QueryService, error) {
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, userCustomerQueries) })
	if s.qs == nil {
		return nil, fmt.Errorf("query service not available")
	}
	return s.qs, nil
}

// CustomerID returns the user's provider customer, or "" when none is linked.
func (s *UserCustomerService) CustomerID(ctx context.Context, userID int) (string, error) {
	qs, err := s.queries(ctx)
	if err != nil {
		return "", err
	}
	res, err := qs.Query(ctx, qUserCustomerToken, userID, s.Provider)
	if err != nil {
		return "", fmt.Errorf("user customer token: %w", err)
	}
	if len(res.Rows) == 0 {
		return "", nil
	}
	return common.AsString(res.Rows[0][0]), nil
}

// LinkCustomer keeps the first customer linked to the user; later calls no-op.
func (s *UserCustomerService) LinkCustomer(ctx context.Context, userID int, customerID string) error {
	if userID <= 0 || customerID == "" {
		return fmt.Errorf("LinkCustomer: userID and customerID required")
	}
	qs, err := s.queries(ctx)
	if err != nil {
		return err
	}
	if _, err := qs.Query(ctx, qUserCustomerLink, userID, s.Provider, customerID); err != nil {
		return fmt.Errorf("link user customer: %w", err)
	}
	return nil
}
