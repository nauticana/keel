package common

import (
	"errors"
	"math"
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
