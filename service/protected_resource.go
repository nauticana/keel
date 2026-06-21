package service

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nauticana/keel/common"
)

// ProtectedResourceMetadataPath is the well-known route for RFC 9728
// OAuth 2.0 Protected Resource Metadata.
const ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource"

// ProtectedResourceMetadata is the RFC 9728 document served at
// ProtectedResourceMetadataPath. It tells OAuth / MCP clients which
// authorization server(s) issue tokens for this resource and which scopes
// it supports.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// ProtectedResourceMetadataFromFlags builds the metadata from the --oauth_*
// flags. Resource falls back to --oauth_audience when --oauth_resource is empty.
func ProtectedResourceMetadataFromFlags() ProtectedResourceMetadata {
	resource := *common.OAuthResource
	if resource == "" {
		resource = *common.OAuthAudience
	}
	return ProtectedResourceMetadata{
		Resource:             resource,
		AuthorizationServers: []string{*common.OAuthIssuer},
		ScopesSupported:      splitCSV(*common.OAuthScopesSupported),
	}
}

// ProtectedResourceMetadataHandler serves meta as keyless JSON. Mount it at
// ProtectedResourceMetadataPath — it is discovery data and takes no auth.
func ProtectedResourceMetadataHandler(meta ProtectedResourceMetadata) http.HandlerFunc {
	if len(meta.BearerMethodsSupported) == 0 {
		meta.BearerMethodsSupported = []string{"header"}
	}
	body, _ := json.Marshal(meta)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
