package common

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestDialPublicOnlyRefusesInternalAddresses(t *testing.T) {
	for addr, public := range map[string]bool{
		"127.0.0.1:443": false, "10.1.2.3:443": false, "169.254.169.254:80": false, "100.64.0.1:443": false,
		"0.0.0.0:443": false, "[::1]:443": false, "[::ffff:192.168.0.1]:443": false, "[fe80::1]:443": false,
		"[fd00::1]:443": false, "8.8.8.8:443": true, "[2001:4860:4860::8888]:443": true,
	} {
		err := DialPublicOnly("tcp", addr, nil)
		if (err == nil) != public {
			t.Errorf("DialPublicOnly(%s) = %v, want public=%v", addr, err, public)
		}
		if err != nil && !errors.Is(err, ErrNonPublicAddress) {
			t.Errorf("DialPublicOnly(%s) = %v, want ErrNonPublicAddress", addr, err)
		}
	}
	if IsPublicAddr(netip.Addr{}) {
		t.Fatal("the zero address is not public")
	}
	if err := DialPublicOnly("tcp", "not-an-address", nil); !errors.Is(err, ErrNonPublicAddress) {
		t.Fatalf("DialPublicOnly(malformed) = %v", err)
	}
}

func TestPublicHTTPClientRefusesLoopbackServer(t *testing.T) {
	withResponseCap(t, 1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a loopback server must never be reached")
	}))
	defer srv.Close()
	if _, _, err := RequestJSONWith(context.Background(), PublicHTTPClient(), http.MethodGet, srv.URL, nil, nil); !errors.Is(err, ErrNonPublicAddress) {
		t.Fatalf("PublicHTTPClient(loopback) = %v, want ErrNonPublicAddress", err)
	}
}
