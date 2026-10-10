package common

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// MaxCIDRList bounds a stored network allow-list; that many IPv6 /128
// entries fit a VARCHAR(2000).
const MaxCIDRList = 32

var ErrInvalidCIDRList = errors.New("invalid network allow-list")

// ParseCIDRList parses a CSV of CIDRs or bare addresses into masked prefixes;
// an empty list allows any address.
func ParseCIDRList(csv string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range SplitCSV(csv) {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, aerr := netip.ParseAddr(raw)
			if aerr != nil {
				return nil, fmt.Errorf("%w: %q is not a CIDR or address", ErrInvalidCIDRList, raw)
			}
			p = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
		}
		out = append(out, p.Masked())
	}
	if len(out) > MaxCIDRList {
		return nil, fmt.Errorf("%w: more than %d entries", ErrInvalidCIDRList, MaxCIDRList)
	}
	return out, nil
}

// FormatCIDRList is the canonical CSV of prefixes, "" for none.
func FormatCIDRList(prefixes []netip.Prefix) string {
	parts := make([]string, len(prefixes))
	for i, p := range prefixes {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

// CIDRListAllows reports whether ip falls in prefixes; an empty list allows
// any address and an unparseable ip none.
func CIDRListAllows(prefixes []netip.Prefix, ip string) bool {
	if len(prefixes) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
