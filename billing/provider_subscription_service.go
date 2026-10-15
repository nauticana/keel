package billing

import (
	"context"
	"errors"
	"fmt"

	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

var (
	// ErrNoProviderSubscription: the active subscription is not managed by the payment provider.
	ErrNoProviderSubscription = errors.New("subscription is not managed by the payment provider")
	// ErrNoProviderCustomer: the partner has no customer at the payment provider.
	ErrNoProviderCustomer = errors.New("no provider customer on file")
)

// ProviderSubscription is the partner's live subscription; ID is the provider's
// subscription id, empty when the provider does not hold it.
type ProviderSubscription struct {
	ID     string
	PlanID string
	Terms  BillingTerms
}

// ProviderSubscriptionStore reads what a subscription change needs.
type ProviderSubscriptionStore interface {
	CustomerToken(ctx context.Context, partnerID int64, provider string) (string, error)
	// CurrentSubscription returns ErrNoSubscription when the partner has no live subscription.
	CurrentSubscription(ctx context.Context, partnerID int64) (*ProviderSubscription, error)
	ProviderPriceID(ctx context.Context, planID string, terms BillingTerms) (string, error)
	// PlanActivationMode returns ErrPlanNotFound for a missing or inactive plan.
	PlanActivationMode(ctx context.Context, planID string) (ActivationMode, error)
}

// ChangeOutcome reports how a plan change took effect.
type ChangeOutcome string

const (
	ChangeApplied   ChangeOutcome = "changed"   // the new plan is active now
	ChangeScheduled ChangeOutcome = "scheduled" // the new plan starts when the current one ends
)

// SubscriptionManager is the self-service contract behind an app's billing page.
type SubscriptionManager interface {
	CancelAtPeriodEnd(ctx context.Context, partnerID int64) error
	ChangePlan(ctx context.Context, partnerID int64, planID string) (ChangeOutcome, error)
	// CheckChange previews what blocks ChangePlan to planID.
	CheckChange(ctx context.Context, partnerID int64, planID string) ([]port.QuotaOverage, error)
	PortalURL(ctx context.Context, partnerID int64) (string, error)
}

// ProviderSubscriptionService changes provider-managed subscriptions. The
// provider is updated first and the local row follows, so a provider failure
// leaves local state untouched; the provider's webhooks confirm later. A move
// to a free plan also applies to a subscription the provider does not hold.
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

// ChangePlan to a free plan ends a provider-held subscription at period end
// with the free plan scheduled as its successor, and replaces any other
// subscription at once. A paid target needs a provider-held subscription.
// Re-selecting the current plan resumes renewal, undoing a scheduled change.
func (s *ProviderSubscriptionService) ChangePlan(ctx context.Context, partnerID int64, planID string) (ChangeOutcome, error) {
	mode, err := s.Store.PlanActivationMode(ctx, planID)
	if err != nil {
		return "", err
	}
	sub, err := s.Store.CurrentSubscription(ctx, partnerID)
	if mode == ActivateFree && errors.Is(err, ErrNoSubscription) {
		return ChangeApplied, s.Lifecycle.ChangePlan(ctx, partnerID, planID, BillingTerms{})
	}
	if err != nil {
		return "", err
	}
	if planID == sub.PlanID {
		return ChangeApplied, s.resumeRenewal(ctx, partnerID, sub)
	}
	if mode == ActivateFree {
		if sub.ID == "" {
			return ChangeApplied, s.Lifecycle.ChangePlan(ctx, partnerID, planID, BillingTerms{})
		}
		if err := s.Client.CancelSubscriptionAtPeriodEnd(ctx, sub.ID); err != nil {
			return "", fmt.Errorf("provider cancel of %s: %w", sub.ID, err)
		}
		return ChangeScheduled, s.Lifecycle.ScheduleChange(ctx, partnerID, planID)
	}
	if sub.ID == "" {
		return "", ErrNoProviderSubscription
	}
	// Refuse before the provider is touched, so a refused downgrade bills nothing.
	overages, err := s.Lifecycle.CheckChange(ctx, partnerID, planID)
	if err != nil {
		return "", err
	}
	if len(overages) > 0 {
		return "", &OverTargetLimitError{PlanID: planID, Overages: overages}
	}
	to, err := s.Store.ProviderPriceID(ctx, planID, sub.Terms)
	if err != nil {
		return "", err
	}
	// The current price only picks the item on a multi-item subscription.
	from, err := s.Store.ProviderPriceID(ctx, sub.PlanID, sub.Terms)
	if err != nil && !errors.Is(err, ErrPriceNotFound) {
		return "", err
	}
	if err := s.Client.ChangeSubscriptionPrice(ctx, sub.ID, from, to, s.ProrationBehavior); err != nil {
		return "", fmt.Errorf("provider plan change of %s: %w", sub.ID, err)
	}
	return ChangeApplied, s.Lifecycle.ChangePlan(ctx, partnerID, planID, sub.Terms)
}

// resumeRenewal clears a scheduled cancellation at the provider (a price
// change onto the current price, which also clears cancel_at_period_end) and locally.
func (s *ProviderSubscriptionService) resumeRenewal(ctx context.Context, partnerID int64, sub *ProviderSubscription) error {
	if sub.ID != "" {
		price, err := s.Store.ProviderPriceID(ctx, sub.PlanID, sub.Terms)
		if err != nil {
			return err
		}
		if err := s.Client.ChangeSubscriptionPrice(ctx, sub.ID, price, price, ""); err != nil {
			return fmt.Errorf("provider renewal of %s: %w", sub.ID, err)
		}
	}
	return s.Lifecycle.ResumeRenewal(ctx, partnerID)
}

func (s *ProviderSubscriptionService) CheckChange(ctx context.Context, partnerID int64, planID string) ([]port.QuotaOverage, error) {
	return s.Lifecycle.CheckChange(ctx, partnerID, planID)
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
	sub, err := s.Store.CurrentSubscription(ctx, partnerID)
	if err != nil {
		return nil, err
	}
	if sub.ID == "" {
		return nil, ErrNoProviderSubscription
	}
	return sub, nil
}

var _ SubscriptionManager = (*ProviderSubscriptionService)(nil)
