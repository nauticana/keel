package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

const (
	AppleAppSiteAssociationPath = "/.well-known/apple-app-site-association"
	AndroidAssetLinksPath       = "/.well-known/assetlinks.json"
)

// WellKnownHandler serves app-association documents as application/json with
// a direct 200; Apple and Android reject a redirect. Documents maps a route
// path to its JSON body.
type WellKnownHandler struct {
	Documents map[string][]byte
}

// Validate fails wiring on a document that is not JSON.
func (h *WellKnownHandler) Validate() error {
	for path, body := range h.Documents {
		if !json.Valid(body) {
			return fmt.Errorf("well-known document %s is not valid JSON", path)
		}
	}
	return nil
}

func (h *WellKnownHandler) GetPublicRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	routes := make(map[string]func(w http.ResponseWriter, r *http.Request), len(h.Documents))
	for path, body := range h.Documents {
		routes[path] = func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write(body)
			}
		}
	}
	return routes
}
