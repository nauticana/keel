package common

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// MaxCurrencyExponent bounds a minor-unit exponent, as the currency table's
// CHECK does.
const MaxCurrencyExponent = 6

// ErrCurrencyExponent rejects an exponent outside 0..MaxCurrencyExponent.
var ErrCurrencyExponent = errors.New("currency exponent out of range")

// ParseMinorUnits converts a decimal amount ("19.99") to integer minor units at
// the currency's exponent (the currency table's), without passing through
// float64. Precision beyond the exponent is an error, never a rounding.
func ParseMinorUnits(amount string, exponent int) (int64, error) {
	if exponent < 0 || exponent > MaxCurrencyExponent {
		return 0, fmt.Errorf("%w: %d", ErrCurrencyExponent, exponent)
	}
	text := strings.TrimSpace(amount)
	negative := strings.HasPrefix(text, "-")
	whole, fraction, _ := strings.Cut(strings.TrimPrefix(text, "-"), ".")
	if whole == "" || !isDigits(whole) || !isDigits(fraction) || len(fraction) > exponent {
		return 0, fmt.Errorf("amount %q is not a decimal with at most %d places", amount, exponent)
	}
	limit := uint64(math.MaxInt64)
	if negative {
		limit++
	}
	var minor uint64
	for _, r := range whole + fraction + strings.Repeat("0", exponent-len(fraction)) {
		digit := uint64(r - '0')
		if minor > (limit-digit)/10 {
			return 0, fmt.Errorf("amount %q overflows int64 minor units", amount)
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

// FormatMinorUnits renders minor units at the currency's exponent, without the
// code ("12.50", "1250", "1.250").
func FormatMinorUnits(minor int64, exponent int) (string, error) {
	if exponent < 0 || exponent > MaxCurrencyExponent {
		return "", fmt.Errorf("%w: %d", ErrCurrencyExponent, exponent)
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
	return digits, nil
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
