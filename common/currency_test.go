package common

import (
	"math"
	"testing"
)

func TestCurrencyExponent(t *testing.T) {
	cases := map[string]struct {
		exponent int
		ok       bool
	}{"USD": {2, true}, "JPY": {0, true}, "BHD": {3, true}, "CLF": {4, true}, "EUR": {2, true}, "ZZZ": {0, false}, "usd": {0, false}, "US": {0, false}, "": {0, false}}
	for code, want := range cases {
		got, ok := CurrencyExponent(code)
		if ok != want.ok || got != want.exponent {
			t.Errorf("%q = %d,%v; want %d,%v", code, got, ok, want.exponent, want.ok)
		}
	}
}

func TestParseMinorUnits(t *testing.T) {
	cases := []struct {
		amount, currency string
		want             int64
		ok               bool
	}{
		{"19.99", "USD", 1999, true},
		{"19.9", "usd", 1990, true},
		{"19", "USD", 1900, true},
		{"19.990", "USD", 0, false},
		{"-0.05", "EUR", -5, true},
		{"1250", "JPY", 1250, true},
		{"1.250", "BHD", 1250, true},
		{"19.999", "USD", 0, false},
		{"1.5", "JPY", 0, false},
		{".5", "USD", 0, false},
		{"1e3", "USD", 0, false},
		{"1.2.3", "USD", 0, false},
		{"", "USD", 0, false},
		{"1", "ZZZ", 0, false},
		{"92233720368547758.07", "USD", 9223372036854775807, true},
		{"92233720368547758.08", "USD", 0, false},
		{"-92233720368547758.08", "USD", math.MinInt64, true},
		{"-92233720368547758.09", "USD", 0, false},
	}
	for _, c := range cases {
		got, err := ParseMinorUnits(c.amount, c.currency)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("ParseMinorUnits(%q, %q) = %d, %v; want %d, ok=%v", c.amount, c.currency, got, err, c.want, c.ok)
		}
	}
}

func TestFormatMinorUnits(t *testing.T) {
	cases := []struct {
		minor    int64
		currency string
		want     string
	}{
		{1250, "USD", "12.50"},
		{5, "usd", "0.05"},
		{-5, "EUR", "-0.05"},
		{0, "USD", "0.00"},
		{1250, "JPY", "1250"},
		{1250, "BHD", "1.250"},
		{math.MinInt64, "JPY", "-9223372036854775808"},
	}
	for _, c := range cases {
		got, ok := FormatMinorUnits(c.minor, c.currency)
		if !ok || got != c.want {
			t.Errorf("FormatMinorUnits(%d, %q) = %q, %v; want %q", c.minor, c.currency, got, ok, c.want)
		}
		if back, err := ParseMinorUnits(got, c.currency); err != nil || back != c.minor {
			t.Errorf("round trip %q = %d, %v; want %d", got, back, err, c.minor)
		}
	}
	if _, ok := FormatMinorUnits(1, "ZZZ"); ok {
		t.Error("unknown currency must report false")
	}
}
