package payment

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

// AddonReconciler brings a metered add-on's quantity in line with a partner's
// current usage. The add-on-quantity mechanism is provider-specific (Stripe
// models it as a subscription_item quantity; LemonSqueezy/Paddle differ), so
// this is an interface with a per-provider impl. Reconcile is best-effort and
// MUST be a complete no-op when unconfigured.
type AddonReconciler interface {
	Reconcile(ctx context.Context, partnerID int64) error
}

// StripeAddonReconciler reconciles a per-unit add-on as a SECOND subscription
// ITEM on the partner's existing subscription (single invoice, clean
// proration). It is INERT when PriceID == "" (a deploy with no add-on Price
// set does nothing — makes test deploys safe) or when SubIDFor returns "" (the
// partner has no eligible provider subscription). The DB-bound bits — how to
// count the desired quantity and how to resolve the subscription id — are
// injected as closures so this stays project-agnostic.
type StripeAddonReconciler struct {
	Stripe  *StripeCheckoutClient
	PriceID string

	// DesiredQty returns the add-on quantity the partner SHOULD be billed for,
	// already clamped to the project's included/cap policy.
	DesiredQty func(ctx context.Context, partnerID int64) (int64, error)

	// SubIDFor returns the provider subscription id to attach the add-on to,
	// or "" when the partner has no eligible subscription (→ no-op).
	SubIDFor func(ctx context.Context, partnerID int64) (string, error)
}

// stripeSubItem is the minimal shape read back from
// GET /subscriptions/{id}?expand[]=items.data. Defensive: any field Stripe
// omits stays zero-valued.
type stripeSubItem struct {
	ID       string `json:"id"`
	Quantity int64  `json:"quantity"`
	Price    struct {
		ID string `json:"id"`
	} `json:"price"`
}

type stripeSubItemsEnvelope struct {
	Items struct {
		Data []stripeSubItem `json:"data"`
	} `json:"items"`
}

func (r *StripeAddonReconciler) Reconcile(ctx context.Context, partnerID int64) error {
	if r.PriceID == "" {
		return nil // INERT — unconfigured; makes zero provider calls
	}
	subID, err := r.SubIDFor(ctx, partnerID)
	if err != nil {
		return err
	}
	if subID == "" {
		return nil // no eligible subscription
	}
	desiredQty, err := r.DesiredQty(ctx, partnerID)
	if err != nil {
		return err
	}

	body, err := r.Stripe.Get(ctx, "/subscriptions/"+subID, url.Values{"expand[]": {"items.data"}})
	if err != nil {
		return err
	}
	var sub stripeSubItemsEnvelope
	if err := json.Unmarshal(body, &sub); err != nil {
		return err
	}
	var itemID string
	var currentQty int64
	for _, it := range sub.Items.Data {
		if it.Price.ID == r.PriceID {
			itemID = it.ID
			currentQty = it.Quantity
			break
		}
	}

	switch {
	case desiredQty > 0 && itemID != "" && currentQty != desiredQty:
		// Update the existing add-on quantity.
		_, err = r.Stripe.Post(ctx, "/subscription_items/"+itemID, url.Values{
			"quantity":           {strconv.FormatInt(desiredQty, 10)},
			"proration_behavior": {"create_prorations"},
		})
		return err
	case desiredQty > 0 && itemID == "":
		// Add the add-on item to the existing subscription.
		_, err = r.Stripe.Post(ctx, "/subscription_items", url.Values{
			"subscription":       {subID},
			"price":              {r.PriceID},
			"quantity":           {strconv.FormatInt(desiredQty, 10)},
			"proration_behavior": {"create_prorations"},
		})
		return err
	case desiredQty == 0 && itemID != "":
		// Remove the add-on item (back down to the included quantity).
		_, err = r.Stripe.Post(ctx, "/subscriptions/"+subID, url.Values{
			"items[0][id]":       {itemID},
			"items[0][deleted]":  {"true"},
			"proration_behavior": {"create_prorations"},
		})
		return err
	default:
		// Already in sync.
		return nil
	}
}

var _ AddonReconciler = (*StripeAddonReconciler)(nil)
