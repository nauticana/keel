package common

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"

	"github.com/nauticana/keel/config"
)

// ErrNonPublicAddress: the resolved address is private, loopback, link-local,
// shared address space, or otherwise not reachable on the public internet.
var ErrNonPublicAddress = errors.New("outbound: address is not public")

var (
	publicOnce   sync.Once
	publicClient *http.Client
	sharedSpace  = netip.MustParsePrefix("100.64.0.0/10")
)

// IsPublicAddr reports whether a is a public unicast address.
func IsPublicAddr(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	return a.IsGlobalUnicast() && !a.IsPrivate() && !sharedSpace.Contains(a)
}

// DialPublicOnly is a net.Dialer Control that refuses non-public addresses.
// It runs after resolution, so a public name pointing at an internal address
// is refused too.
func DialPublicOnly(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNonPublicAddress, address)
	}
	if !IsPublicAddr(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrNonPublicAddress, ap.Addr())
	}
	return nil
}

// PublicHTTPClient is HTTPClient for URLs an untrusted party chose, such as a
// partner's own host: it dials public addresses only and ignores proxies.
func PublicHTTPClient() *http.Client {
	publicOnce.Do(func() {
		cfg := config.Config()
		dialer := &net.Dialer{Timeout: cfg.DefaultOutboundTimeout, Control: DialPublicOnly}
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.Proxy = nil
		base.DialContext = dialer.DialContext
		var transport http.RoundTripper = base
		if cfg.OutboundMaxRPS > 0 {
			transport = &rateLimitedTransport{base: base, limiter: newOutboundLimiter(cfg.OutboundMaxRPS)}
		}
		publicClient = &http.Client{Timeout: cfg.DefaultOutboundTimeout, Transport: transport, CheckRedirect: checkRedirect}
	})
	return publicClient
}
