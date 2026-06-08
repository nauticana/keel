package service

import (
	"context"
	"fmt"
	"strconv"

	"github.com/nauticana/keel/payment"
)

// ProviderSubscriptionEventHandler is the default provider-driven PaymentEventHandler:
// the standard webhook→billing mapping every SaaS hand-writes, pre-wired onto a
// payment.AbstractWebhookEventHandler. A project constructs it from its billing
// service (which satisfies both SubscriptionLifecycle and ProviderBillingStore)
// plus a few options, registers it with the WebhookProcessor, and its own
// payment_service.go collapses to that wiring.
//
// It lives in service (not payment) on purpose: it drives the service-layer
// lifecycle verbs, and service already depends on payment — the reverse import
// would be a cycle. It IS a payment.PaymentEventHandler via the embedded
// dispatcher, so it plugs in wherever one is expected.
type ProviderSubscriptionEventHandler struct {
	*payment.AbstractWebhookEventHandler
}

// SubscriptionHandlerOptions parameterizes the default mapping. The only thing
// that genuinely varies between projects is partner resolution and the metadata
// key names; everything else is the standard sentence.
type SubscriptionHandlerOptions struct {
	// PartnerIDKey is the checkout-metadata key holding the partner id
	// (default "partner_id"). Read as int64 for the default resolver.
	PartnerIDKey string
	// PlanIDKey is the checkout-metadata key holding the plan id (default "plan_id").
	PlanIDKey string

	// ResolvePartner overrides partner resolution entirely — supply this when the
	// id you stash is not the partner id (e.g. a user_id you map via UserService).
	// When nil, the default resolver tries metadata[PartnerIDKey] then the
	// customer-token reverse lookup (ProviderBillingStore.PartnerByCustomer).
	ResolvePartner func(ctx context.Context, e *payment.PaymentEvent) (int64, error)

	// OnSubscriptionUpdated is an optional passthrough for customer.subscription.updated
	// (seat / plan reconcile — the canonical event carries no quantity, so the
	// project owns this). nil = ignore.
	OnSubscriptionUpdated func(ctx context.Context, e *payment.PaymentEvent) error

	// RecordPayment is an optional audit writer fired after a paid invoice is
	// recorded (e.g. the project's payment_record ledger). nil = skip.
	RecordPayment func(ctx context.Context, partnerID int64, e *payment.PaymentEvent) error
}

// NewProviderSubscriptionEventHandler wires the standard mapping:
//   - checkout_completed → LinkCustomer + Activate (per the plan's activation_mode)
//   - setup_completed    → LinkCustomer (vault the customer for self-scheduled billing)
//   - invoice_paid       → RecordProviderInvoice + ConvertTrial (+ optional RecordPayment)
//   - invoice_payment_failed → SetDunningState past-due ('X')
//   - subscription_updated   → opts.OnSubscriptionUpdated (optional)
//   - subscription_canceled  → CancelByProviderSubID, falling back to CancelByPartner
//
// checkout_completed always ACTIVATES a new subscription — it does NOT detect a
// plan change, so a subscriber who re-checks-out for a different plan gets a
// second active row, not a switch. Route upgrades/downgrades through ChangePlan
// (e.g. from opts.OnSubscriptionUpdated), not a fresh checkout.
//
// life and store are usually the same *AbstractBillingService passed twice.
func NewProviderSubscriptionEventHandler(life SubscriptionLifecycle, store ProviderBillingStore, opts SubscriptionHandlerOptions) *ProviderSubscriptionEventHandler {
	if opts.PartnerIDKey == "" {
		opts.PartnerIDKey = "partner_id"
	}
	if opts.PlanIDKey == "" {
		opts.PlanIDKey = "plan_id"
	}

	resolve := func(ctx context.Context, e *payment.PaymentEvent) (int64, error) {
		if opts.ResolvePartner != nil {
			return opts.ResolvePartner(ctx, e)
		}
		if id := metaInt(e.Metadata, opts.PartnerIDKey); id > 0 {
			return id, nil
		}
		if e.CustomerID != "" {
			return store.PartnerByCustomer(ctx, e.Provider, e.CustomerID)
		}
		return 0, fmt.Errorf("provider subscription handler: cannot resolve partner for event %q", e.ProviderEventID)
	}

	h := &ProviderSubscriptionEventHandler{}
	h.AbstractWebhookEventHandler = &payment.AbstractWebhookEventHandler{
		OnCheckoutCompleted: func(ctx context.Context, e *payment.PaymentEvent) error {
			partnerID, err := resolve(ctx, e)
			if err != nil {
				return err
			}
			if e.CustomerID != "" {
				if err := store.LinkCustomer(ctx, partnerID, e.Provider, e.CustomerID); err != nil {
					return err
				}
			}
			return life.Activate(ctx, partnerID, e.Metadata[opts.PlanIDKey], e.SubscriptionID, metaInt(e.Metadata, "seats"))
		},

		OnSetupCompleted: func(ctx context.Context, e *payment.PaymentEvent) error {
			if e.CustomerID == "" {
				return nil
			}
			partnerID, err := resolve(ctx, e)
			if err != nil {
				return err
			}
			return store.LinkCustomer(ctx, partnerID, e.Provider, e.CustomerID)
		},

		OnInvoicePaid: func(ctx context.Context, e *payment.PaymentEvent) error {
			partnerID, err := resolve(ctx, e)
			if err != nil {
				return err
			}
			if err := store.RecordProviderInvoice(ctx, partnerID, e); err != nil {
				return err
			}
			// no-op unless the sub is trialing — first paid invoice converts it.
			if err := life.ConvertTrial(ctx, partnerID); err != nil {
				return err
			}
			if opts.RecordPayment != nil {
				return opts.RecordPayment(ctx, partnerID, e)
			}
			return nil
		},

		OnInvoicePaymentFailed: func(ctx context.Context, e *payment.PaymentEvent) error {
			partnerID, err := resolve(ctx, e)
			if err != nil {
				return err
			}
			return life.SetDunningState(ctx, partnerID, "X")
		},

		OnSubscriptionUpdated: opts.OnSubscriptionUpdated,

		OnSubscriptionCanceled: func(ctx context.Context, e *payment.PaymentEvent) error {
			// Prefer the provider-sub-id path (the webhook's own subscription);
			// fall back to a partner-wide cancel when no local row matched.
			if e.SubscriptionID != "" {
				n, err := life.CancelByProviderSubID(ctx, e.SubscriptionID, CancelImmediate)
				if err != nil {
					return err
				}
				if n > 0 {
					return nil
				}
			}
			partnerID, err := resolve(ctx, e)
			if err != nil {
				return err
			}
			return life.CancelByPartner(ctx, partnerID, CancelImmediate)
		},
	}
	return h
}

// metaInt reads an int64 from an event-metadata map; 0 when absent/unparsable.
func metaInt(m map[string]string, key string) int64 {
	if key == "" {
		return 0
	}
	if v, ok := m[key]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

var _ payment.PaymentEventHandler = (*ProviderSubscriptionEventHandler)(nil)
