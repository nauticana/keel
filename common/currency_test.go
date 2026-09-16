package common

import "testing"

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
