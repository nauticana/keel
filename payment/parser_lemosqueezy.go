package payment

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LemonSqueezyEventParser turns a LemonSqueezy webhook body into a
// canonical PaymentEvent. LemonSqueezy amounts already come as strings
// in major units.
type LemonSqueezyEventParser struct{}

func NewLemonSqueezyEventParser() *LemonSqueezyEventParser { return &LemonSqueezyEventParser{} }

// PeekEventMeta satisfies EventParser — pulls just the event id and
// event_name out of the raw body for the idempotency pre-pass. Empty id
// returns are propagated; the processor rejects them.
func (p *LemonSqueezyEventParser) PeekEventMeta(body []byte) (string, string, error) {
	var peek struct {
		Meta struct {
			EventName string `json:"event_name"`
		} `json:"meta"`
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return "", "", err
	}
	return peek.Data.ID, peek.Meta.EventName, nil
}

// Parse satisfies port.EventParser.
func (p *LemonSqueezyEventParser) Parse(body []byte) (*PaymentEvent, error) {
	var raw struct {
		Meta struct {
			EventName  string            `json:"event_name"`
			CustomData map[string]string `json:"custom_data"`
		} `json:"meta"`
		Data struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse lemonsqueezy event: %w", err)
	}

	if raw.Data.ID == "" {
		// Same idempotency-preservation logic as the Stripe path:
		// LemonSqueezy webhooks have no built-in replay window
		// (signature alone is HMAC-SHA256 over the body), so the only
		// thing keeping an attacker who captured a single valid pair
		// from replaying it forever is the event-id dedupe in
		// payment_webhook_log. Refuse to fabricate one.
		return nil, fmt.Errorf("lemonsqueezy event missing data.id")
	}
	event := &PaymentEvent{
		Provider:        ProviderLemonSqueezy,
		ProviderEventID: raw.Data.ID,
		EventType:       raw.Meta.EventName,
		RawPayload:      string(body),
		Metadata:        map[string]string{},
	}
	for k, v := range raw.Meta.CustomData {
		event.Metadata[k] = v
	}

	event.EventKind = lemonSqueezyEventKind(raw.Meta.EventName)
	switch {
	case strings.HasPrefix(raw.Meta.EventName, "subscription_payment_"):
		event.InvoiceID = raw.Data.ID // the subscription-invoice id
	case strings.HasPrefix(raw.Meta.EventName, "subscription_"):
		event.SubscriptionID = raw.Data.ID
	}

	attr := raw.Data.Attributes
	if attr == nil {
		return event, nil
	}
	// amount — LemonSqueezy commonly uses "total" or "total_usd" in cents.
	// Same sign / zero-amount tolerance as the Stripe path: refunds,
	// voids, and setup-mode events must propagate with the right
	// numeric value, not be silently zeroed out (P1-11).
	for _, key := range []string{"total_usd", "total", "amount"} {
		if raw, ok := attr[key]; ok {
			if cents, ok := asInt64(raw); ok {
				event.MinorUnits = cents
				event.Amount = float64(cents) / 100.0
				break
			}
		}
	}
	if c, ok := attr["currency"].(string); ok {
		event.Currency = strings.ToUpper(c)
	}
	if ts, ok := attr["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			event.PaidAt = t
		}
	}
	if event.SubscriptionID == "" {
		if v, ok := attr["subscription_id"]; ok {
			event.SubscriptionID = fmt.Sprintf("%v", v)
		}
	}
	return event, nil
}

// lemonSqueezyEventKind maps a raw LemonSqueezy event_name onto the
// provider-agnostic PaymentEvent.EventKind. Unmapped names return KindOther.
func lemonSqueezyEventKind(eventName string) string {
	switch eventName {
	case "subscription_created", "order_created":
		return KindCheckoutCompleted
	case "subscription_payment_success":
		return KindInvoicePaid
	case "subscription_payment_failed":
		return KindInvoicePaymentFailed
	case "subscription_updated", "subscription_plan_changed", "subscription_resumed", "subscription_unpaused":
		return KindSubscriptionUpdated
	case "subscription_cancelled", "subscription_expired":
		return KindSubscriptionCanceled
	}
	return KindOther
}
