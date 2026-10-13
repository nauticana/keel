package common

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestParseMinorUnits(t *testing.T) {
	cases := []struct {
		amount   string
		exponent int
		want     int64
		ok       bool
	}{
		{"19.99", 2, 1999, true},
		{"19.9", 2, 1990, true},
		{"19", 2, 1900, true},
		{"19.990", 2, 0, false},
		{"-0.05", 2, -5, true},
		{"1250", 0, 1250, true},
		{"1.250", 3, 1250, true},
		{"19.999", 2, 0, false},
		{"1.5", 0, 0, false},
		{".5", 2, 0, false},
		{"1e3", 2, 0, false},
		{"1.2.3", 2, 0, false},
		{"", 2, 0, false},
		{"1", -1, 0, false},
		{"92233720368547758.07", 2, 9223372036854775807, true},
		{"92233720368547758.08", 2, 0, false},
		{"-92233720368547758.08", 2, math.MinInt64, true},
		{"-92233720368547758.09", 2, 0, false},
	}
	for _, c := range cases {
		got, err := ParseMinorUnits(c.amount, c.exponent)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("ParseMinorUnits(%q, %d) = %d, %v; want %d, ok=%v", c.amount, c.exponent, got, err, c.want, c.ok)
		}
	}
}

func TestFormatMinorUnits(t *testing.T) {
	cases := []struct {
		minor    int64
		exponent int
		want     string
	}{
		{1250, 2, "12.50"},
		{5, 2, "0.05"},
		{-5, 2, "-0.05"},
		{0, 2, "0.00"},
		{1250, 0, "1250"},
		{1250, 3, "1.250"},
		{math.MinInt64, 0, "-9223372036854775808"},
	}
	for _, c := range cases {
		got, err := FormatMinorUnits(c.minor, c.exponent)
		if err != nil || got != c.want {
			t.Errorf("FormatMinorUnits(%d, %d) = %q, %v; want %q", c.minor, c.exponent, got, err, c.want)
		}
		if back, err := ParseMinorUnits(got, c.exponent); err != nil || back != c.minor {
			t.Errorf("round trip %q = %d, %v; want %d", got, back, err, c.minor)
		}
	}
	for _, e := range []int{-1, MaxCurrencyExponent + 1} {
		if _, err := FormatMinorUnits(1, e); !errors.Is(err, ErrCurrencyExponent) {
			t.Errorf("FormatMinorUnits exponent %d: %v", e, err)
		}
		if _, err := ParseMinorUnits("1", e); !errors.Is(err, ErrCurrencyExponent) {
			t.Errorf("ParseMinorUnits exponent %d: %v", e, err)
		}
	}
}

func TestRoundMinorUnits(t *testing.T) {
	for _, c := range []struct {
		amount   string
		exponent int
		want     int64
	}{
		{"1234.5600000000002", 2, 123456},
		{"19.995", 2, 2000},
		{"-19.995", 2, -2000},
		{"1250.4", 0, 1250},
		{"1250.5", 0, 1251},
		{"1.2345", 3, 1235},
		{"1e3", 2, 100000},
		{"1E-40", 2, 0},
		{".5", 0, 1},
		{"", 2, 0},
	} {
		got, err := RoundMinorUnits(c.amount, c.exponent)
		if err != nil || got != c.want {
			t.Errorf("RoundMinorUnits(%q, %d) = %d, %v; want %d", c.amount, c.exponent, got, err, c.want)
		}
	}
	for _, bad := range []string{"abc", "1/3", "NaN", "Inf", "0x10", "-+1", "1e41", "1e999999999", "1e", ".", "99999999999999999999", strings.Repeat("0", maxDecimalInput+1)} {
		if _, err := RoundMinorUnits(bad, 2); err == nil {
			t.Errorf("RoundMinorUnits(%q) must fail", bad)
		}
	}
	if _, err := RoundMinorUnits("1", 7); !errors.Is(err, ErrCurrencyExponent) {
		t.Errorf("exponent 7 = %v", err)
	}
}

func TestDivRound(t *testing.T) {
	for _, c := range []struct{ minor, n, want int64 }{
		{5, 2, 3}, {-5, 2, -3}, {4, 3, 1}, {-4, 3, -1},
		{math.MaxInt64, 2, math.MaxInt64/2 + 1}, {math.MinInt64, 3, math.MinInt64/3 - 1},
	} {
		if got := DivRound(c.minor, c.n); got != c.want {
			t.Errorf("DivRound(%d, %d) = %d, want %d", c.minor, c.n, got, c.want)
		}
	}
}
