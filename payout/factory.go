package payout

import (
	"fmt"

	"github.com/nauticana/keel/logger"
)

// NewProvider returns a PayoutProvider impl for the given 2-char code:
//
//	"AW" Airwallex (default)
//	"SC" Stripe Connect
//	"WI" Wise
//
// All providers obey the same PayoutProvider contract — adding a new
// one is a new file + a new switch arm here. apiKey and webhookSecret
// are pulled from the application's secret backend at boot.
func NewProvider(code, apiKey, webhookSecret string, journal logger.ApplicationLogger) (PayoutProvider, error) {
	switch code {
	case "AW", "":
		return NewAirwallexProvider(apiKey, webhookSecret, journal)
	case "SC":
		return NewStripeConnectProvider(apiKey, webhookSecret, journal)
	case "WI":
		return NewWiseProvider(apiKey, webhookSecret, journal)
	default:
		return nil, fmt.Errorf("payout: unknown provider code %q", code)
	}
}
