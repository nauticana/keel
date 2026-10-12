// Package telephony reads what a phone system reports back: it verifies an
// inbound webhook with the account's signing secret and decodes it into
// provider-neutral call and message events.
package telephony

import "net/http"

// Webhook is a provider's request as received. URL is the public URL the
// provider called, which some signature schemes cover; Body is the raw body.
type Webhook struct {
	URL    string
	Header http.Header
	Body   []byte
}

// Provider verifies and decodes one phone system's webhooks.
type Provider interface {
	Name() string
	// Events returns nothing, without error, for a verified delivery that
	// reports no final call or message state.
	Events(webhook Webhook, signingSecret string) ([]Event, error)
	// Ack is the response the provider expects for an accepted delivery.
	Ack() (contentType, body string)
}
