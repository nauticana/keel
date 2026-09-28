package payout

import (
	"fmt"

	"github.com/nauticana/keel/common"
)

// minorToDecimal renders minor units as the exact major-unit decimal a
// provider's amount field expects (599 USD → "5.99", JPY → "599", BHD →
// "0.599"). Stripe takes minor units directly and must NOT use this.
func minorToDecimal(amount int64, currency string) (string, error) {
	decimal, ok := common.FormatMinorUnits(amount, currency)
	if !ok {
		return "", fmt.Errorf("payout: unknown currency %q", currency)
	}
	return decimal, nil
}
