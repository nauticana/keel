package handler

import (
	"testing"

	"github.com/nauticana/keel/common"
)

// Every route ConsentHandler mounts must clear SSOMiddleware's partner gate:
// signup records consent before the partner exists, so a gated route would 403
// for exactly the users it serves.
func TestConsentRoutesArePartnerOptional(t *testing.T) {
	h := &ConsentHandler{}
	routes := h.GetAuthRoutes()
	if len(routes) == 0 {
		t.Fatal("ConsentHandler mounted no routes")
	}
	for path := range routes {
		if !common.IsPartnerOptional(path) {
			t.Errorf("route %q is not partner-optional; SSOMiddleware would 403 it during signup", path)
		}
	}
}
