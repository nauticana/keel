package billing

import (
	"context"

	"github.com/nauticana/keel/payment"
)

// BillingEngine is the swappable recurring-billing strategy: ProviderSubscriptionEngine
// lets the provider run the cycle (react to webhooks); SelfScheduledEngine runs it
// itself and charges off-session.
type BillingEngine interface {
	// EnsureSubscription ensures an active sub (no-op for provider-driven).
	EnsureSubscription(ctx context.Context, partnerID int64, planID string) error
	// HandleEvent reacts to a provider webhook (provider-driven only).
	HandleEvent(ctx context.Context, e *payment.PaymentEvent) error
	// RunCycle runs one billing pass (self-scheduled only; no-op otherwise).
	RunCycle(ctx context.Context) error
}

// ProviderSubscriptionEngine delegates the cycle to the payment provider and
// reacts to its webhooks via the injected AbstractWebhookEventHandler.
type ProviderSubscriptionEngine struct {
	Handler *payment.AbstractWebhookEventHandler
}

func (e *ProviderSubscriptionEngine) EnsureSubscription(ctx context.Context, partnerID int64, planID string) error {
	return nil // provider checkout + webhook activates the subscription
}

func (e *ProviderSubscriptionEngine) HandleEvent(ctx context.Context, ev *payment.PaymentEvent) error {
	if e.Handler == nil {
		return nil
	}
	return e.Handler.OnPaymentEvent(ctx, ev)
}

func (e *ProviderSubscriptionEngine) RunCycle(ctx context.Context) error { return nil }

var _ BillingEngine = (*ProviderSubscriptionEngine)(nil)
