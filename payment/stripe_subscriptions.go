package payment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

// CancelSubscriptionAtPeriodEnd stops renewal; Stripe emits
// customer.subscription.deleted when the period ends.
func (c *StripeCheckoutClient) CancelSubscriptionAtPeriodEnd(ctx context.Context, subscriptionID string) error {
	if subscriptionID == "" {
		return errors.New("stripe: subscription id is required")
	}
	_, err := c.Post(ctx, "/subscriptions/"+url.PathEscape(subscriptionID), url.Values{"cancel_at_period_end": {"true"}})
	return err
}

// ChangeSubscriptionPrice moves the item billed at fromPriceID to toPriceID; a
// single-item subscription changes its only item.
func (c *StripeCheckoutClient) ChangeSubscriptionPrice(ctx context.Context, subscriptionID, fromPriceID, toPriceID, prorationBehavior string) error {
	if subscriptionID == "" || toPriceID == "" {
		return errors.New("stripe: subscription id and target price are required")
	}
	path := "/subscriptions/" + url.PathEscape(subscriptionID)
	body, err := c.Get(ctx, path, nil)
	if err != nil {
		return err
	}
	var sub struct {
		Items struct {
			Data []struct {
				ID    string `json:"id"`
				Price struct {
					ID string `json:"id"`
				} `json:"price"`
			} `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &sub); err != nil {
		return fmt.Errorf("stripe: parse subscription: %w", err)
	}
	itemID := ""
	alreadyChanged := false
	for _, item := range sub.Items.Data {
		if len(sub.Items.Data) == 1 || item.Price.ID == fromPriceID {
			itemID = item.ID
			break
		}
		if item.Price.ID == toPriceID {
			alreadyChanged = true
		}
	}
	if itemID == "" && alreadyChanged {
		return nil
	}
	if itemID == "" {
		return fmt.Errorf("stripe: subscription %s has no item priced %q", subscriptionID, fromPriceID)
	}
	form := url.Values{"items[0][id]": {itemID}, "items[0][price]": {toPriceID}}
	if prorationBehavior != "" {
		form.Set("proration_behavior", prorationBehavior)
	}
	_, err = c.Post(ctx, path, form)
	return err
}

var _ SubscriptionClient = (*StripeCheckoutClient)(nil)
