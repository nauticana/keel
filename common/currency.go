package common

import "golang.org/x/text/currency"

// CurrencyExponent returns the ISO 4217 minor-unit exponent for an uppercase
// three-letter code (USD → 2, JPY → 0, BHD → 3), or false for an unknown code.
// Money in ledgers is integer minor units; never assume two decimals.
func CurrencyExponent(code string) (int, bool) {
	unit, err := currency.ParseISO(code)
	if err != nil || unit.String() != code {
		return 0, false
	}
	exponent, _ := currency.Standard.Rounding(unit)
	return exponent, true
}
