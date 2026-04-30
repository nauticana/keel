package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/common"
)

// B6: TrustedClientIP must ignore X-Forwarded-For when the inbound
// peer is not in --trusted_proxy_cidr. Trvoo's previous header-trusting
// clientIP would have returned the spoofed value.
func TestTrustedClientIP_UntrustedPeer_IgnoresForwardedFor(t *testing.T) {
	saved := *common.TrustedProxyCIDR
	*common.TrustedProxyCIDR = "10.0.0.0/8"
	defer func() { *common.TrustedProxyCIDR = saved }()

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:54321" // public IP, not in the trusted CIDR
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")

	got := TrustedClientIP(r)
	if got != "203.0.113.5" {
		t.Fatalf("untrusted peer must return RemoteAddr host: got %q, want 203.0.113.5", got)
	}
}

// When the peer is in --trusted_proxy_cidr, X-Forwarded-For's leftmost
// entry is honored (the original client; the rest of the chain is the
// proxy hop list).
func TestTrustedClientIP_TrustedPeer_HonorsForwardedFor(t *testing.T) {
	saved := *common.TrustedProxyCIDR
	*common.TrustedProxyCIDR = "10.0.0.0/8"
	defer func() { *common.TrustedProxyCIDR = saved }()

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.99")

	got := TrustedClientIP(r)
	if got != "1.2.3.4" {
		t.Fatalf("trusted peer must honor leftmost XFF entry: got %q, want 1.2.3.4", got)
	}
}

// Empty --trusted_proxy_cidr means trust nothing — even private peers
// don't get their headers honored.
func TestTrustedClientIP_EmptyConfig_TrustsNothing(t *testing.T) {
	saved := *common.TrustedProxyCIDR
	*common.TrustedProxyCIDR = ""
	defer func() { *common.TrustedProxyCIDR = saved }()

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := TrustedClientIP(r)
	if got != "10.0.0.5" {
		t.Fatalf("empty config must return RemoteAddr host: got %q, want 10.0.0.5", got)
	}
}

// B8: RequireTrustedProxyCIDR rejects the empty default — the
// production opt-in turns the library-safe default into a deploy-time
// failure.
func TestRequireTrustedProxyCIDR_EmptyConfig_Errors(t *testing.T) {
	saved := *common.TrustedProxyCIDR
	*common.TrustedProxyCIDR = ""
	defer func() { *common.TrustedProxyCIDR = saved }()

	if err := RequireTrustedProxyCIDR(); err == nil {
		t.Fatal("expected error for empty config, got nil")
	}
}

// B8: a config that splits to zero parseable CIDRs is the same broken
// state as empty — getTrustedProxyNets silently drops bad entries, so
// the validator must reject too.
func TestRequireTrustedProxyCIDR_AllInvalid_Errors(t *testing.T) {
	saved := *common.TrustedProxyCIDR
	*common.TrustedProxyCIDR = "not-a-cidr,also-bad,"
	defer func() { *common.TrustedProxyCIDR = saved }()

	if err := RequireTrustedProxyCIDR(); err == nil {
		t.Fatal("expected error for all-invalid config, got nil")
	}
}

// B8: a single valid CIDR in the list is enough to pass validation,
// even when other entries are bogus (matches the runtime cache's
// best-effort parsing).
func TestRequireTrustedProxyCIDR_HasValidEntry_OK(t *testing.T) {
	saved := *common.TrustedProxyCIDR
	*common.TrustedProxyCIDR = "garbage, 10.0.0.0/8 ,  "
	defer func() { *common.TrustedProxyCIDR = saved }()

	if err := RequireTrustedProxyCIDR(); err != nil {
		t.Fatalf("expected nil for partially-valid config, got %v", err)
	}
}
