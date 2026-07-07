package resource

import (
	"encoding/json"
	"net/http"

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

// ProtectedResourceMetadataFromConfig builds the metadata from the --oauth_*
// flags. Resource falls back to oauth_audience when oauth_resource is empty.
func ProtectedResourceMetadataFromConfig() ProtectedResourceMetadata {
	resource := common.Config().OAuthResource
	if resource == "" {
		resource = common.Config().OAuthAudience
	}
	return ProtectedResourceMetadata{
		Resource:             resource,
		AuthorizationServers: []string{common.Config().OAuthIssuer},
		ScopesSupported:      common.SplitCSV(common.Config().OAuthScopesSupported),
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
