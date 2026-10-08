// Package oidc is keel's OpenID Connect relying party: discovery, ID-token
// verification, the authorization-code flow with PKCE, client authentication
// by secret or private_key_jwt, the tenant connection provider behind
// port.IdentityProvider, and the first-party Google and Apple verifiers.
package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/nauticana/keel/common"
)

// Discovery is the subset of an OpenID Provider configuration keel reads.
type Discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	SigningAlgorithms     []string `json:"id_token_signing_alg_values_supported"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// FetchDiscovery reads the configuration at discoveryURL and requires its
// issuer to equal issuer exactly. A templated issuer, such as a multi-tenant
// authority's "{tenantid}", is refused, as is any non-HTTPS endpoint.
func FetchDiscovery(ctx context.Context, httpc *http.Client, discoveryURL, issuer string) (*Discovery, error) {
	if err := requireHTTPS(discoveryURL); err != nil {
		return nil, fmt.Errorf("%w: discovery url: %v", ErrBadConfiguration, err)
	}
	if issuer == "" || strings.ContainsAny(issuer, "{}") {
		return nil, fmt.Errorf("%w: issuer %q", ErrBadConfiguration, issuer)
	}
	body, _, err := common.RequestJSONWith(ctx, httpc, http.MethodGet, discoveryURL, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery %s: %w", discoveryURL, err)
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("%w: discovery document: %v", ErrBadConfiguration, err)
	}
	if d.Issuer != issuer {
		return nil, fmt.Errorf("%w: discovery issuer %q is not %q", ErrBadConfiguration, d.Issuer, issuer)
	}
	for name, endpoint := range map[string]string{"authorization_endpoint": d.AuthorizationEndpoint, "token_endpoint": d.TokenEndpoint, "jwks_uri": d.JWKSURI} {
		if err := requireHTTPS(endpoint); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrBadConfiguration, name, err)
		}
	}
	if len(d.SigningAlgorithms) == 0 {
		return nil, fmt.Errorf("%w: no id_token signing algorithms advertised", ErrBadConfiguration)
	}
	return &d, nil
}

// supportsAuth reports whether the issuer accepts method at its token
// endpoint; an issuer that lists nothing accepts client_secret_basic only.
func (d *Discovery) supportsAuth(method string) bool {
	if len(d.TokenAuthMethods) == 0 {
		return method == AuthSecretBasic
	}
	return slices.Contains(d.TokenAuthMethods, method)
}

func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("%q is not an absolute https URL", raw)
	}
	return nil
}
