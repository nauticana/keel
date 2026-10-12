package schema

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
)

// The currency seed is the only source of exponents, so it is checked here.
func TestCurrencySeed(t *testing.T) {
	seeds, err := ParseSeedPath("seed/geo.yml")
	if err != nil {
		t.Fatal(err)
	}
	exponents := map[string]string{}
	for _, st := range seeds[0].Seeds {
		if st.Table != "currency" {
			continue
		}
		code, exponent := seedColumn(st, "code"), seedColumn(st, "exponent")
		for _, r := range st.Rows {
			c, e := fmt.Sprint(r[code]), fmt.Sprint(r[exponent])
			if len(c) != 3 || strings.Trim(c, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" || exponents[c] != "" {
				t.Errorf("currency %q is malformed or duplicated", c)
			}
			if len(e) != 1 || e[0] < '0' || int(e[0]-'0') > common.MaxCurrencyExponent {
				t.Errorf("currency %s exponent %s out of range", c, e)
			}
			exponents[c] = e
		}
	}
	want := map[string]string{"USD": "2", "EUR": "2", "JPY": "0", "KRW": "0", "CLP": "0", "ISK": "0",
		"COP": "2", "IDR": "2", "BHD": "3", "KWD": "3", "IQD": "3", "CLF": "4"}
	for _, c := range strings.Fields("ALL ARS AUD BAM BGN BOB BRL BYN CAD CHF CLP COP CZK DKK EUR GBP GYD HUF " +
		"ISK MDL MKD MXN NOK PEN PLN PYG RON RSD SEK SRD TRY UAH USD UYU VES CNY INR JPY KRW BHD KWD") {
		if exponents[c] == "" {
			t.Errorf("currency %s missing from the seed", c)
		}
	}
	for c, e := range want {
		if exponents[c] != e {
			t.Errorf("currency %s exponent %q, want %s", c, exponents[c], e)
		}
	}
}
