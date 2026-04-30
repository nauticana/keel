package payment

import (
	"encoding/json"
	"fmt"
	"time"
)

// LemonSqueezyEventParser turns a LemonSqueezy webhook body into a
// canonical PaymentEvent. LemonSqueezy amounts already come as strings
// in major units.
type LemonSqueezyEventParser struct{}

func NewLemonSqueezyEventParser() *LemonSqueezyEventParser { return &LemonSqueezyEventParser{} }

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
		Provider:        "lemonsqueezy",
		ProviderEventID: raw.Data.ID,
		EventType:       raw.Meta.EventName,
		RawPayload:      string(body),
		Metadata:        map[string]string{},
	}
	for k, v := range raw.Meta.CustomData {
		event.Metadata[k] = v
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
		event.Currency = toUpperASCII(c)
	}
	if ts, ok := attr["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			event.PaidAt = t
		}
	}
	return event, nil
}
