package payment

import (
	"errors"
	"math"
	"testing"
)

func TestMulDivFloor(t *testing.T) {
	got, err := MulDivFloor(math.MaxInt64, math.MaxInt64, math.MaxInt64)
	if err != nil || got != math.MaxInt64 {
		t.Fatalf("MulDivFloor exact large result = %d, %v", got, err)
	}
	if _, err = MulDivFloor(-1, 2, 3); !errors.Is(err, ErrMoneyArithmetic) {
		t.Fatalf("negative apportionment should fail: %v", err)
	}
}

func TestMulDivRoundHalfEven(t *testing.T) {
	cases := []struct {
		a, b, den, want int64
	}{
		{5, 1, 10, 0},
		{15, 1, 10, 2},
		{25, 1, 10, 2},
		{-15, 1, 10, -2},
		{2499, 2000, 10000, 500},
	}
	for _, tc := range cases {
		got, err := MulDivRoundHalfEven(tc.a, tc.b, tc.den)
		if err != nil || got != tc.want {
			t.Errorf("MulDivRoundHalfEven(%d,%d,%d) = %d, %v; want %d", tc.a, tc.b, tc.den, got, err, tc.want)
		}
	}
}
