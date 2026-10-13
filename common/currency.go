package common

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// MaxCurrencyExponent bounds a minor-unit exponent, as the currency table's
// CHECK does.
const MaxCurrencyExponent = 6

// ErrCurrencyExponent rejects an exponent outside 0..MaxCurrencyExponent.
var ErrCurrencyExponent = errors.New("currency exponent out of range")

// maxDecimalInput bounds work performed for untrusted provider values.
const maxDecimalInput = 128

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

// RoundMinorUnits converts a provider's decimal amount ("1234.5600000001",
// "1e3") to minor units at exponent, rounding half away from zero where
// ParseMinorUnits refuses the excess precision. An empty amount is zero.
func RoundMinorUnits(amount string, exponent int) (int64, error) {
	if exponent < 0 || exponent > MaxCurrencyExponent {
		return 0, fmt.Errorf("%w: %d", ErrCurrencyExponent, exponent)
	}
	text := strings.TrimSpace(amount)
	if text == "" {
		return 0, nil
	}
	if len(text) > maxDecimalInput {
		return 0, fmt.Errorf("amount is longer than %d bytes", maxDecimalInput)
	}
	mantissa, power, scientific := strings.Cut(strings.ToLower(text), "e")
	if strings.HasPrefix(mantissa, "-") || strings.HasPrefix(mantissa, "+") {
		mantissa = mantissa[1:]
	}
	whole, fraction, _ := strings.Cut(mantissa, ".")
	valid := whole+fraction != "" && isDigits(whole) && isDigits(fraction)
	if p, err := strconv.Atoi(power); scientific && (err != nil || p < -maxDecimalInput || p > maxDecimalInput) {
		valid = false
	}
	if !valid {
		return 0, fmt.Errorf("amount %q is not a decimal", amount)
	}
	r, ok := new(big.Rat).SetString(text)
	if !ok {
		return 0, fmt.Errorf("amount %q is not a decimal", amount)
	}
	r.Mul(r, new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil)))
	num, den := new(big.Int).Abs(r.Num()), r.Denom()
	minor := new(big.Int).Quo(new(big.Int).Add(new(big.Int).Lsh(num, 1), den), new(big.Int).Lsh(den, 1))
	if r.Sign() < 0 {
		minor.Neg(minor)
	}
	if !minor.IsInt64() {
		return 0, fmt.Errorf("amount %q overflows int64 minor units", amount)
	}
	return minor.Int64(), nil
}

// DivRound divides minor units by n > 0, rounding half away from zero, without
// the overflow of adding n/2 first.
func DivRound(minor, n int64) int64 {
	if n <= 0 {
		panic("common.DivRound: divisor must be positive")
	}
	q, r := minor/n, minor%n
	if r < 0 {
		r = -r
	}
	if r >= n-r {
		if minor < 0 {
			q--
		} else {
			q++
		}
	}
	return q
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
