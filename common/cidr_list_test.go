package common

import (
	"errors"
	"strings"
	"testing"
)

func TestCIDRList(t *testing.T) {
	nets, err := ParseCIDRList(" 10.1.2.3/8, 2001:db8::1 ,192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if got := FormatCIDRList(nets); got != "10.0.0.0/8,2001:db8::1/128,192.0.2.7/32" {
		t.Fatalf("canonical = %q", got)
	}
	for ip, want := range map[string]bool{"10.200.0.1": true, "::ffff:10.0.0.1": true, "2001:db8::1": true, "192.0.2.8": false, "": false, "bogus": false} {
		if CIDRListAllows(nets, ip) != want {
			t.Errorf("%q allowed = %v", ip, !want)
		}
	}
	if !CIDRListAllows(nil, "") {
		t.Error("an empty list allows any address")
	}
	if nets, err := ParseCIDRList(""); err != nil || nets != nil {
		t.Fatalf("empty = %v, %v", nets, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "host.example", strings.Repeat("10.0.0.1,", MaxCIDRList+1)} {
		if _, err := ParseCIDRList(bad); !errors.Is(err, ErrInvalidCIDRList) {
			t.Errorf("%.30q: %v", bad, err)
		}
	}
}
