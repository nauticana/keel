package payment

import (
	"errors"
	"math/big"
)

var ErrMoneyArithmetic = errors.New("money arithmetic overflow or invalid denominator")

// MulDivFloor returns floor(a*b/den) without overflowing int64. It accepts
// non-negative inputs, which is the contract used for money apportionment.
func MulDivFloor(a, b, den int64) (int64, error) {
	if a < 0 || b < 0 || den <= 0 {
		return 0, ErrMoneyArithmetic
	}
	numerator := new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
	quotient := new(big.Int).Quo(numerator, big.NewInt(den))
	if !quotient.IsInt64() {
		return 0, ErrMoneyArithmetic
	}
	return quotient.Int64(), nil
}

// MulDivRoundHalfEven returns a*b/den rounded to the nearest integer, with an
// exact half rounded to the even neighbor. big.Int keeps the intermediate
// product exact and the final int64 range is checked explicitly.
func MulDivRoundHalfEven(a, b, den int64) (int64, error) {
	if den <= 0 {
		return 0, ErrMoneyArithmetic
	}
	numerator := new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
	negative := numerator.Sign() < 0
	abs := new(big.Int).Abs(numerator)
	divisor := big.NewInt(den)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(abs, divisor, remainder)
	comparison := new(big.Int).Lsh(new(big.Int).Set(remainder), 1).Cmp(divisor)
	if comparison > 0 || (comparison == 0 && quotient.Bit(0) == 1) {
		quotient.Add(quotient, big.NewInt(1))
	}
	if negative {
		quotient.Neg(quotient)
	}
	if !quotient.IsInt64() {
		return 0, ErrMoneyArithmetic
	}
	return quotient.Int64(), nil
}
