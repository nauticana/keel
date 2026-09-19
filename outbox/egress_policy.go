package outbox

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

var ErrEgressDenied = errors.New("outbox: webhook egress denied")

// EgressPolicy decides which webhook destinations may be reached. The zero
// value rejects everything.
type EgressPolicy struct {
	// AllowedHosts entries are an exact host, "*.example.com" (subdomains only),
	// or "*" for any host. Addresses are still vetted at dial time.
	AllowedHosts []string
	// AllowPrivateNetworks permits loopback, private, link-local and CGNAT
	// addresses — in-cluster receivers and tests only.
	AllowPrivateNetworks bool
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func (p EgressPolicy) checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not https", ErrEgressDenied, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in URL", ErrEgressDenied)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrEgressDenied)
	}
	if !p.hostAllowed(host) {
		return fmt.Errorf("%w: host %q is not on the allow-list", ErrEgressDenied, host)
	}
	return nil
}

func (p EgressPolicy) hostAllowed(host string) bool {
	for _, pattern := range p.AllowedHosts {
		pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
		switch {
		case pattern == "":
		case pattern == "*", pattern == host:
			return true
		case strings.HasPrefix(pattern, "*."):
			if strings.HasSuffix(host, pattern[1:]) {
				return true
			}
		}
	}
	return false
}

// dialControl vets the resolved address, so a public name pointing at an
// internal address (DNS rebinding) is refused at connect time.
func (p EgressPolicy) dialControl(_, address string, _ syscall.RawConn) error {
	if p.AllowPrivateNetworks {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEgressDenied, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEgressDenied, err)
	}
	addr = addr.Unmap().WithZone("")
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || cgnat.Contains(addr) {
		return fmt.Errorf("%w: address %s is not public", ErrEgressDenied, addr)
	}
	return nil
}
