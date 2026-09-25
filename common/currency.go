package common

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/text/currency"
)

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

// ParseMinorUnits converts a decimal amount ("19.99") to integer minor units of
// currency without passing through float64. Precision beyond the currency's
// exponent is an error, never a rounding.
func ParseMinorUnits(amount, currencyCode string) (int64, error) {
	code := strings.ToUpper(strings.TrimSpace(currencyCode))
	exponent, ok := CurrencyExponent(code)
	if !ok {
		return 0, fmt.Errorf("unknown currency %q", currencyCode)
	}
	text := strings.TrimSpace(amount)
	negative := strings.HasPrefix(text, "-")
	whole, fraction, _ := strings.Cut(strings.TrimPrefix(text, "-"), ".")
	if whole == "" || !isDigits(whole) || !isDigits(fraction) || len(fraction) > exponent {
		return 0, fmt.Errorf("amount %q is not a %s value", amount, code)
	}
	limit := uint64(math.MaxInt64)
	if negative {
		limit++
	}
	var minor uint64
	for _, r := range whole + fraction + strings.Repeat("0", exponent-len(fraction)) {
		digit := uint64(r - '0')
		if minor > (limit-digit)/10 {
			return 0, fmt.Errorf("amount %q overflows %s minor units", amount, code)
		}
		minor = minor*10 + digit
	}
	if negative {
		if minor == uint64(math.MaxInt64)+1 {
			return math.MinInt64, nil
		}
		return -int64(minor), nil
	}
	return int64(minor), nil
}

// FormatMinorUnits renders minor units at the currency's precision, without the
// code ("12.50", "1250", "1.250"); false for an unknown currency.
func FormatMinorUnits(minor int64, currencyCode string) (string, bool) {
	exponent, ok := CurrencyExponent(strings.ToUpper(strings.TrimSpace(currencyCode)))
	if !ok {
		return "", false
	}
	digits := strconv.FormatUint(absUint64(minor), 10)
	if exponent > 0 {
		if len(digits) <= exponent {
			digits = strings.Repeat("0", exponent-len(digits)+1) + digits
		}
		digits = digits[:len(digits)-exponent] + "." + digits[len(digits)-exponent:]
	}
	if minor < 0 {
		digits = "-" + digits
	}
	return digits, true
}

func absUint64(n int64) uint64 {
	if n < 0 {
		return uint64(-(n + 1)) + 1
	}
	return uint64(n)
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
