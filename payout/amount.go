package payout

import (
	"errors"

	"github.com/nauticana/keel/common"
)

// errNoExponent refuses a decimal-wire payout without the currency exponent:
// guessing it would rescale the amount.
var errNoExponent = errors.New("currency exponent required")

// decimalAmount renders the input's minor units as the exact major-unit decimal
// a provider's amount field expects (599 USD → "5.99", JPY → "599", BHD →
// "0.599"). Stripe takes minor units directly and must NOT use this.
func decimalAmount(in InstantPayoutInput) (string, error) {
	if in.Exponent == nil {
		return "", errNoExponent
	}
	return common.FormatMinorUnits(in.Amount, *in.Exponent)
}
