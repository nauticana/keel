package payment

import "context"

// AbstractWebhookEventHandler implements PaymentEventHandler by dispatching
// the canonical PaymentEvent.EventKind to per-kind function hooks. A project
// constructs it with only the hooks it cares about; a nil hook is a no-op
// (returns nil), preserving the "unhandled event = nil" behavior consumers
// relied on with their hand-rolled `switch e.EventType` blocks.
//
// Provider-agnostic by construction: it keys on EventKind (set by each
// EventParser) rather than a provider's raw event strings, so the same hooks
// fire whether the event came from Stripe, LemonSqueezy, etc.
type AbstractWebhookEventHandler struct {
	OnCheckoutCompleted    func(ctx context.Context, e *PaymentEvent) error
	OnInvoiceFinalized     func(ctx context.Context, e *PaymentEvent) error
	OnInvoicePaid          func(ctx context.Context, e *PaymentEvent) error
	OnInvoicePaymentFailed func(ctx context.Context, e *PaymentEvent) error
	OnSubscriptionUpdated  func(ctx context.Context, e *PaymentEvent) error
	OnSubscriptionCanceled func(ctx context.Context, e *PaymentEvent) error
	OnSetupCompleted       func(ctx context.Context, e *PaymentEvent) error

	// OnOther receives any event whose EventKind matched no specific hook
	// (including KindOther). Nil = ignore.
	OnOther func(ctx context.Context, e *PaymentEvent) error
}

func (h *AbstractWebhookEventHandler) OnPaymentEvent(ctx context.Context, e *PaymentEvent) error {
	var hook func(ctx context.Context, e *PaymentEvent) error
	switch e.EventKind {
	case KindCheckoutCompleted:
		hook = h.OnCheckoutCompleted
	case KindInvoiceFinalized:
		hook = h.OnInvoiceFinalized
	case KindInvoicePaid:
		hook = h.OnInvoicePaid
	case KindInvoicePaymentFailed:
		hook = h.OnInvoicePaymentFailed
	case KindSubscriptionUpdated:
		hook = h.OnSubscriptionUpdated
	case KindSubscriptionCanceled:
		hook = h.OnSubscriptionCanceled
	case KindSetupCompleted:
		hook = h.OnSetupCompleted
	}
	if hook == nil {
		hook = h.OnOther
	}
	if hook == nil {
		return nil
	}
	return hook(ctx, e)
}

var _ PaymentEventHandler = (*AbstractWebhookEventHandler)(nil)
