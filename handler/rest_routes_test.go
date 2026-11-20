package handler

import (
	"testing"

	"github.com/nauticana/keel/rest"
)

func TestRestHandlerRoutes(t *testing.T) {
	h := &RestHandler{Api: rest.RestAPI{APIName: "widget", Version: "v2"}}
	routes := h.Routes("/api")
	for _, op := range []string{"get", "list", "post", "delete", "export"} {
		if routes["/api/v2/widget/"+op] == nil {
			t.Errorf("missing %s route", op)
		}
	}
	if len(routes) != 5 {
		t.Errorf("routes = %d, want 5", len(routes))
	}
}
