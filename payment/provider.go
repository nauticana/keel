package payment

import (
	"context"

	"github.com/nauticana/keel/secret"
)

// AbstractProvider is the base implementation of port.PaymentProvider.
// Concrete providers (Stripe, LemonSqueezy) compose this with their
// specific verifier, parser, name, and header.
type AbstractProvider struct {
	ProviderName string
	SigHeader    string
	Verifier     SignatureVerifier
	Parser       EventParser
}

func (a *AbstractProvider) Name() string            { return a.ProviderName }
func (a *AbstractProvider) SignatureHeader() string { return a.SigHeader }

func (a *AbstractProvider) Verify(ctx context.Context, sigHeader string, body []byte) error {
	return a.Verifier.Verify(ctx, sigHeader, body)
}

func (a *AbstractProvider) Parse(body []byte) (*PaymentEvent, error) {
	return a.Parser.Parse(body)
}

// StripeProvider bundles verifier + parser for Stripe.
type StripeProvider struct{ AbstractProvider }

func NewStripeProvider(secrets secret.SecretProvider) *StripeProvider {
	return &StripeProvider{
		AbstractProvider: AbstractProvider{
			ProviderName: "stripe",
			SigHeader:    "Stripe-Signature",
			Verifier:     NewStripeSignatureVerifier(secrets),
			Parser:       NewStripeEventParser(),
		},
	}
}

// LemonSqueezyProvider bundles verifier + parser for LemonSqueezy.
type LemonSqueezyProvider struct{ AbstractProvider }

func NewLemonSqueezyProvider(secrets secret.SecretProvider) *LemonSqueezyProvider {
	return &LemonSqueezyProvider{
		AbstractProvider: AbstractProvider{
			ProviderName: "lemonsqueezy",
			SigHeader:    "X-Signature",
			Verifier:     NewLemonSqueezySignatureVerifier(secrets),
			Parser:       NewLemonSqueezyEventParser(),
		},
	}
}

// compile-time interface checks
var (
	_ PaymentProvider = (*AbstractProvider)(nil)
	_ PaymentProvider = (*StripeProvider)(nil)
	_ PaymentProvider = (*LemonSqueezyProvider)(nil)
)
