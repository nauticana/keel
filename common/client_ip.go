package common

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/nauticana/keel/config"
)

// TrustedClientIP honors X-Forwarded-For / X-Real-IP only when the socket
// peer is inside trusted_proxy_cidr; otherwise any client could spoof its IP.
// Empty config trusts nothing and returns the peer address.
func TrustedClientIP(r *http.Request) string {
	remote := RemoteHost(r.RemoteAddr)
	if !isTrustedProxy(remote) {
		return remote
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// leftmost entry is the original client
		if comma := strings.IndexByte(xff, ','); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	if real := r.Header.Get("X-Real-IP"); real != "" {
		return strings.TrimSpace(real)
	}
	return remote
}

// RequireTrustedProxyCIDR errors unless trusted_proxy_cidr holds at least one
// parseable entry. Call it at boot in deployments that record client IPs.
func RequireTrustedProxyCIDR() error {
	cfg := strings.TrimSpace(config.Config().TrustedProxyCIDR)
	if cfg == "" {
		return fmt.Errorf("trusted_proxy_cidr must be set when mounting public IP-attributing endpoints; received empty value")
	}
	if len(getTrustedProxyNets(cfg)) == 0 {
		return fmt.Errorf("trusted_proxy_cidr=%q parsed to zero valid CIDR entries", cfg)
	}
	return nil
}

func MustRequireTrustedProxyCIDR() {
	if err := RequireTrustedProxyCIDR(); err != nil {
		log.Fatalf("trusted-proxy config: %v", err)
	}
}

// RemoteHost returns the host part of a "host:port" peer address.
func RemoteHost(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// Parsed CIDR set, re-parsed only when the config value changes.
var (
	trustedProxyMu   sync.Mutex
	trustedProxyKey  string
	trustedProxyNets []*net.IPNet
)

func isTrustedProxy(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	cfg := config.Config().TrustedProxyCIDR
	if cfg == "" {
		return false
	}
	nets := getTrustedProxyNets(cfg)
	if len(nets) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func getTrustedProxyNets(cfg string) []*net.IPNet {
	trustedProxyMu.Lock()
	defer trustedProxyMu.Unlock()
	if cfg == trustedProxyKey {
		return trustedProxyNets
	}
	var nets []*net.IPNet
	for _, raw := range strings.Split(cfg, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(raw); err == nil && n != nil {
			nets = append(nets, n)
		}
	}
	trustedProxyKey = cfg
	trustedProxyNets = nets
	return nets
}
