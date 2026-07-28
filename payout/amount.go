package payout

import (
	"fmt"
	"strconv"

	"github.com/nauticana/keel/payment"
)

// minorToDecimal renders an integer minor-unit amount as the exact
// major-unit decimal string a provider's currency-amount field expects
// ("599" USD → "5.99", "599" JPY → "599", "599" BHD → "0.599").
// Pure integer math — never float64 — so the wire value is exact.
// Stripe takes minor units directly and must NOT use this.
func minorToDecimal(amount int64, currency string) string {
	exp := payment.CurrencyExponent(currency)
	if exp == 0 {
		return strconv.FormatInt(amount, 10)
	}
	sign := ""
	if amount < 0 {
		sign = "-"
		amount = -amount
	}
	scale := int64(1)
	for i := 0; i < exp; i++ {
		scale *= 10
	}
	return fmt.Sprintf("%s%d.%0*d", sign, amount/scale, exp, amount%scale)
}
