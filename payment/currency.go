package payment

import (
	"math"
	"strings"
)

// Money is represented authoritatively as integer minor units (int64). These
// tables convert to/from the major-unit decimal value used only for display and
// NUMERIC storage. Source: ISO 4217.

// zeroDecimalCurrencies have no minor unit — the integer amount IS the value
// (Stripe treats the `amount` parameter the same way for these).
var zeroDecimalCurrencies = map[string]bool{
	"BIF": true, "CLP": true, "DJF": true, "GNF": true, "JPY": true,
	"KMF": true, "KRW": true, "MGA": true, "PYG": true, "RWF": true,
	"UGX": true, "VND": true, "VUV": true, "XAF": true, "XOF": true,
	"XPF": true,
}

// threeDecimalCurrencies use 1/1000 minor units.
var threeDecimalCurrencies = map[string]bool{
	"BHD": true, "IQD": true, "JOD": true, "KWD": true, "LYD": true,
	"OMR": true, "TND": true,
}

// CurrencyExponent returns the number of minor-unit decimal places for an ISO
// 4217 code (case-insensitive): 0 for zero-decimal currencies (JPY, KRW, …),
// 3 for three-decimal currencies (BHD, KWD, …), 2 otherwise.
func CurrencyExponent(currency string) int {
	switch c := strings.ToUpper(strings.TrimSpace(currency)); {
	case zeroDecimalCurrencies[c]:
		return 0
	case threeDecimalCurrencies[c]:
		return 3
	default:
		return 2
	}
}

// MinorToMajor converts an integer minor-unit amount to its major-unit decimal
// value for the currency — for display / NUMERIC storage only, never for math
// that must stay exact (keep that in int64 minor units).
func MinorToMajor(minor int64, currency string) float64 {
	scale := 1.0
	for i := 0; i < CurrencyExponent(currency); i++ {
		scale *= 10
	}
	return float64(minor) / scale
}

// MajorToMinor converts a major-unit decimal amount (e.g. an operator-entered
// price) to integer minor units for the currency, using CurrencyExponent so
// JPY (0 places) and BHD (3) are correct rather than a hardcoded ×100. Rounded
// to nearest to absorb float-precision noise at the input boundary; keep all
// downstream math in the returned int64.
func MajorToMinor(major float64, currency string) int64 {
	scale := 1.0
	for i := 0; i < CurrencyExponent(currency); i++ {
		scale *= 10
	}
	return int64(math.Round(major * scale))
}
