package payout

import (
	"fmt"

	"github.com/nauticana/keel/logger"
)

// NewProvider returns a PayoutProvider impl for the given 2-char code.
// Accepts the ProviderCode* constants from payout_interfaces.go:
//
//	ProviderCodeAirwallex     ("AW") — default
//	ProviderCodeStripeConnect ("SC")
//	ProviderCodeWise          ("WI")
//
// All providers obey the same PayoutProvider contract — adding a new
// one is a new file + a new switch arm here. apiKey and webhookSecret
// are pulled from the application's secret backend at boot.
func NewProvider(code, apiKey, webhookSecret string, journal logger.ApplicationLogger) (PayoutProvider, error) {
	switch code {
	case ProviderCodeAirwallex, "":
		return NewAirwallexProvider(apiKey, webhookSecret, journal)
	case ProviderCodeStripeConnect:
		return NewStripeConnectProvider(apiKey, webhookSecret, journal)
	case ProviderCodeWise:
		return NewWiseProvider(apiKey, webhookSecret, journal)
	default:
		return nil, fmt.Errorf("payout: unknown provider code %q", code)
	}
}
