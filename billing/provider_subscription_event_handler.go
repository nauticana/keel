package billing

import (
	"context"
	"fmt"
	"strconv"

	"github.com/nauticana/keel/payment"
)

// ProviderSubscriptionEventHandler is the default provider-driven webhook→billing
// mapping, pre-wired onto a payment.AbstractWebhookEventHandler. Construct it from
// the billing service (which satisfies SubscriptionLifecycle + ProviderBillingStore)
// and register it with the WebhookProcessor.
type ProviderSubscriptionEventHandler struct {
	*payment.AbstractWebhookEventHandler
}

// SubscriptionHandlerOptions parameterizes the default mapping — mainly partner
// resolution and the checkout-metadata key names.
type SubscriptionHandlerOptions struct {
	PartnerIDKey string // default "partner_id"
	PlanIDKey    string // default "plan_id"
	// Chosen offer keys (PERIOD_TYPE codes + count); defaults
	// "billing_cycle"/"term_type"/"term_count". Absent → monthly, 1-month term.
	BillingCycleKey string
	TermTypeKey     string
	TermCountKey    string

	// ResolvePartner overrides partner resolution (e.g. a user_id mapped via
	// UserService). nil → metadata[PartnerIDKey] then PartnerByCustomer.
	ResolvePartner func(ctx context.Context, e *payment.PaymentEvent) (int64, error)
	// OnSubscriptionUpdated handles seat/plan reconcile (canonical event carries no
	// quantity, so the project owns it). nil = ignore.
	OnSubscriptionUpdated func(ctx context.Context, e *payment.PaymentEvent) error
	// RecordPayment is an optional audit writer after a paid invoice. nil = skip.
	RecordPayment func(ctx context.Context, partnerID int64, e *payment.PaymentEvent) error
}

// NewProviderSubscriptionEventHandler wires the standard mapping:
//   - checkout_completed → LinkCustomer + Activate
//   - setup_completed    → LinkCustomer (vault for self-scheduled billing)
//   - invoice_paid       → RecordProviderInvoice + ConvertTrial (+ RecordPayment)
//   - invoice_payment_failed → SetDunningState 'X'
//   - subscription_updated   → opts.OnSubscriptionUpdated
//   - subscription_canceled  → CancelByProviderSubID, fallback CancelByPartner
//
// checkout_completed always activates a NEW sub — it does not detect plan changes;
// route upgrades/downgrades through ChangePlan. life and store are usually the
// same *AbstractBillingService passed twice.
func NewProviderSubscriptionEventHandler(life SubscriptionLifecycle, store ProviderBillingStore, opts SubscriptionHandlerOptions) *ProviderSubscriptionEventHandler {
	if opts.PartnerIDKey == "" {
		opts.PartnerIDKey = "partner_id"
	}
	if opts.PlanIDKey == "" {
		opts.PlanIDKey = "plan_id"
	}
	if opts.BillingCycleKey == "" {
		opts.BillingCycleKey = "billing_cycle"
	}
	if opts.TermTypeKey == "" {
		opts.TermTypeKey = "term_type"
	}
	if opts.TermCountKey == "" {
		opts.TermCountKey = "term_count"
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
			terms := BillingTerms{
				BillingCycle: ParseBillingPeriod(e.Metadata[opts.BillingCycleKey]),
				TermType:     ParseBillingPeriod(e.Metadata[opts.TermTypeKey]),
				TermCount:    int(metaInt(e.Metadata, opts.TermCountKey)),
			}
			return life.Activate(ctx, partnerID, e.Metadata[opts.PlanIDKey], terms, e.SubscriptionID, metaInt(e.Metadata, "seats"))
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
			// Prefer the provider-sub-id; fall back to partner-wide when no row matched.
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
