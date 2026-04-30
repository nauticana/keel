package payment

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// StripeEventParser turns a Stripe webhook body into a canonical
// PaymentEvent. Amounts are normalized from cents to major units.
type StripeEventParser struct{}

func NewStripeEventParser() *StripeEventParser { return &StripeEventParser{} }

// Parse satisfies port.EventParser.
func (p *StripeEventParser) Parse(body []byte) (*PaymentEvent, error) {
	var raw struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Created int64  `json:"created"`
		Data    struct {
			Object map[string]any `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse stripe event: %w", err)
	}

	if raw.ID == "" {
		// Reject rather than fabricate: a synthetic id would defeat
		// idempotency by minting a fresh value on every retry of the
		// same payload. webhook.Process rejects empty ids upstream,
		// but defending here too prevents direct callers of Parse()
		// from accidentally papering over a malformed event.
		return nil, fmt.Errorf("stripe event missing id")
	}
	event := &PaymentEvent{
		Provider:        "stripe",
		ProviderEventID: raw.ID,
		EventType:       raw.Type,
		RawPayload:      string(body),
		Metadata:        map[string]string{},
	}
	if raw.Created > 0 {
		event.PaidAt = time.Unix(raw.Created, 0).UTC()
	}

	obj := raw.Data.Object
	if obj == nil {
		return event, nil
	}

	cents := stripeAmountCents(raw.Type, obj)
	event.MinorUnits = cents
	event.Amount = float64(cents) / 100.0
	event.Currency = stripeCurrency(obj)
	for k, v := range stripeMetadata(obj) {
		event.Metadata[k] = v
	}

	// v0.5.1-D: pre-extract setup-mode-relevant typed fields so domain
	// handlers can `if e.Mode == "setup"` instead of re-parsing the
	// raw body. Stripe carries these on data.object for checkout +
	// setup_intent events; absent on most charge / invoice events.
	if s, ok := obj["mode"].(string); ok {
		event.Mode = s
	}
	if s, ok := obj["customer"].(string); ok {
		event.CustomerID = s
	}
	// SetupIntentID has two sources depending on event class:
	//   - checkout.session.* events spawn a SetupIntent and reference it
	//     via data.object.setup_intent (a string id).
	//   - setup_intent.* events are the SetupIntent itself; data.object.id
	//     is the SetupIntent's id.
	if s, ok := obj["setup_intent"].(string); ok {
		event.SetupIntentID = s
	}
	if event.SetupIntentID == "" && strings.HasPrefix(raw.Type, "setup_intent.") {
		if s, ok := obj["id"].(string); ok {
			event.SetupIntentID = s
		}
	}
	return event, nil
}

// stripeAmountCents reads the canonical amount field (cents) for the
// given event type. Returns 0 when no recognized field is in the
// payload — the value itself may legitimately be zero (setup-mode
// checkouts, payment failures), and the parser must NOT short-circuit
// on that: those events still need to reach the domain handler.
//
// Stripe uses different field names per event type. Dispatching by
// event type matters for refunds: `charge.refunded` carries BOTH
// `amount` (the original charge) AND `amount_refunded` (the refunded
// amount). A naïve "first present" lookup would return the original
// charge amount and the consumer's reconciliation would double-count
// the refund. Refunds are reported as a NEGATIVE minor-unit value so
// downstream ledgers can sum amounts without per-event branching.
func stripeAmountCents(eventType string, obj map[string]any) int64 {
	// Refund-class events: amount_refunded is authoritative; flip the
	// sign so consumers can sum across rows.
	switch eventType {
	case "charge.refunded", "charge.refund.updated":
		if raw, ok := obj["amount_refunded"]; ok {
			if cents, ok := asInt64(raw); ok {
				return -cents
			}
		}
		return 0
	}
	// Per-type preferred field; fall back to a generic order if the
	// preferred slot is absent (older Stripe API versions, custom
	// connect accounts, etc.).
	preferred := map[string]string{
		"checkout.session.completed":     "amount_total",
		"checkout.session.async_payment_succeeded": "amount_total",
		"invoice.paid":                    "amount_paid",
		"invoice.payment_succeeded":       "amount_paid",
		"invoice.payment_failed":          "amount_due",
		"payment_intent.succeeded":        "amount_received",
		"payment_intent.payment_failed":   "amount",
		"payment_intent.amount_capturable_updated": "amount_capturable",
		"charge.succeeded":                "amount",
		"charge.failed":                   "amount",
		"charge.captured":                 "amount_captured",
	}
	if key, ok := preferred[eventType]; ok {
		if raw, ok := obj[key]; ok {
			if cents, ok := asInt64(raw); ok {
				return cents
			}
		}
	}
	for _, key := range []string{"amount_total", "amount_paid", "amount_received", "amount"} {
		if raw, ok := obj[key]; ok {
			if cents, ok := asInt64(raw); ok {
				return cents
			}
		}
	}
	return 0
}

func stripeCurrency(obj map[string]any) string {
	if c, ok := obj["currency"].(string); ok {
		return toUpperASCII(c)
	}
	return ""
}

func stripeMetadata(obj map[string]any) map[string]string {
	md := map[string]string{}
	raw, ok := obj["metadata"].(map[string]any)
	if !ok {
		return md
	}
	for k, v := range raw {
		md[k] = fmt.Sprintf("%v", v)
	}
	return md
}

// compile-time interface checks
var (
	_ EventParser = (*StripeEventParser)(nil)
	_ EventParser = (*LemonSqueezyEventParser)(nil)
)

// asInt64 reads a JSON-decoded numeric value as an int64. Stripe and
// LemonSqueezy both transmit minor-unit amounts as integers, so this
// is the preferred parse path; the float fallback exists only for
// `json.Number`-decoded inputs and tolerates non-integer doubles by
// truncating toward zero.
func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case float32:
		return int64(n), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		if f, err := n.Float64(); err == nil {
			return int64(f), true
		}
	}
	return 0, false
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func toUpperASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		b[i] = c
	}
	return string(b)
}
