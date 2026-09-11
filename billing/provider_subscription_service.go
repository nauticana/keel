package billing

import (
	"context"
	"errors"
	"fmt"

	"github.com/nauticana/keel/payment"
)

var (
	// ErrNoProviderSubscription: the active subscription is not managed by the payment provider.
	ErrNoProviderSubscription = errors.New("subscription is not managed by the payment provider")
	// ErrNoProviderCustomer: the partner has no customer at the payment provider.
	ErrNoProviderCustomer = errors.New("no provider customer on file")
)

// ProviderSubscription is the partner's active subscription as the provider knows it.
type ProviderSubscription struct {
	ID     string
	PlanID string
	Terms  BillingTerms
}

// ProviderSubscriptionStore reads what a provider-side subscription change needs.
type ProviderSubscriptionStore interface {
	CustomerToken(ctx context.Context, partnerID int64, provider string) (string, error)
	ActiveProviderSubscription(ctx context.Context, partnerID int64) (*ProviderSubscription, error)
	ProviderPriceID(ctx context.Context, planID string, terms BillingTerms) (string, error)
}

// SubscriptionManager is the self-service contract behind an app's billing page.
type SubscriptionManager interface {
	CancelAtPeriodEnd(ctx context.Context, partnerID int64) error
	ChangePlan(ctx context.Context, partnerID int64, planID string) error
	PortalURL(ctx context.Context, partnerID int64) (string, error)
}

// ProviderSubscriptionService changes provider-managed subscriptions. The
// provider is updated first and the local row follows, so a provider failure
// leaves local state untouched; the provider's webhooks confirm later.
type ProviderSubscriptionService struct {
	Store     ProviderSubscriptionStore
	Lifecycle SubscriptionLifecycle
	Client    payment.SubscriptionClient
	Portal    payment.CheckoutClient
	Provider  string // e.g. payment.ProviderStripe
	// ProrationBehavior is sent on plan change; empty uses the provider default.
	ProrationBehavior string
	PortalReturnURL   func() string
}

func (s *ProviderSubscriptionService) CancelAtPeriodEnd(ctx context.Context, partnerID int64) error {
	sub, err := s.activeSubscription(ctx, partnerID)
	if err != nil {
		return err
	}
	if err := s.Client.CancelSubscriptionAtPeriodEnd(ctx, sub.ID); err != nil {
		return fmt.Errorf("provider cancel of %s: %w", sub.ID, err)
	}
	return s.Lifecycle.CancelByPartner(ctx, partnerID, CancelAtPeriodEnd)
}

func (s *ProviderSubscriptionService) ChangePlan(ctx context.Context, partnerID int64, planID string) error {
	sub, err := s.activeSubscription(ctx, partnerID)
	if err != nil {
		return err
	}
	if planID == sub.PlanID {
		return nil
	}
	to, err := s.Store.ProviderPriceID(ctx, planID, sub.Terms)
	if err != nil {
		return err
	}
	// The current price only picks the item on a multi-item subscription.
	from, err := s.Store.ProviderPriceID(ctx, sub.PlanID, sub.Terms)
	if err != nil && !errors.Is(err, ErrPriceNotFound) {
		return err
	}
	if err := s.Client.ChangeSubscriptionPrice(ctx, sub.ID, from, to, s.ProrationBehavior); err != nil {
		return fmt.Errorf("provider plan change of %s: %w", sub.ID, err)
	}
	return s.Lifecycle.ChangePlan(ctx, partnerID, planID, sub.Terms)
}

func (s *ProviderSubscriptionService) PortalURL(ctx context.Context, partnerID int64) (string, error) {
	if s.PortalReturnURL == nil {
		return "", errors.New("billing portal return URL is not configured")
	}
	customerID, err := s.Store.CustomerToken(ctx, partnerID, s.Provider)
	if err != nil {
		return "", err
	}
	if customerID == "" {
		return "", ErrNoProviderCustomer
	}
	return s.Portal.CreatePortalSession(ctx, customerID, s.PortalReturnURL())
}

func (s *ProviderSubscriptionService) activeSubscription(ctx context.Context, partnerID int64) (*ProviderSubscription, error) {
	sub, err := s.Store.ActiveProviderSubscription(ctx, partnerID)
	if err != nil {
		return nil, err
	}
	if sub == nil {
		return nil, ErrNoProviderSubscription
	}
	return sub, nil
}

var _ SubscriptionManager = (*ProviderSubscriptionService)(nil)
