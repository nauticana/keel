package client

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// shopHostRe matches a canonical Shopify store host. Anchored so an attacker
// can't smuggle an arbitrary host (e.g. evil.com#.myshopify.com) that would
// otherwise receive the app secret during token exchange.
var shopHostRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.myshopify\.com$`)

// ShopifyProvider connects a merchant's Shopify store. The partner picks a shop
// at AuthURL time; it rides the OAuth state into api_endpoint. Test uses
// Shopify's X-Shopify-Access-Token header (not Bearer), wired via TestHealthcheck.
//
// Config is injected (no app globals): APIKey is the Shopify app's public key,
// SecretName the keystore key holding the app secret, APIVersion the Admin API
// version (e.g. "2025-01"), Scopes the requested access scopes, and RequiredScopes
// the subset that must be granted for the connection to be accepted.
//
// TODO(shopify): new public apps now require expiring offline tokens (expiring=1
// + refresh-token rotation) and GraphQL; this uses the proven non-expiring/REST
// flow — add an opt-in expiring+GraphQL mode before onboarding a new public app.
type ShopifyProvider struct {
	BaseProvider
	APIKey         string
	SecretName     string
	APIVersion     string
	Scopes         string
	RequiredScopes []string
}

var _ Provider = (*ShopifyProvider)(nil)

// NewShopifyProvider builds a Shopify connection provider.
func NewShopifyProvider(svc CredentialStore, name, callbackURL, apiKey, secretName, apiVersion, scopes string, requiredScopes []string) *ShopifyProvider {
	p := &ShopifyProvider{
		BaseProvider:   BaseProvider{Service: svc, CallbackURL: callbackURL, ProviderName: name},
		APIKey:         apiKey,
		SecretName:     secretName,
		APIVersion:     apiVersion,
		Scopes:         scopes,
		RequiredScopes: requiredScopes,
	}
	p.TestHealthcheck = p.testHealthcheck
	return p
}

// canonicalShopDomain validates and normalizes a user-supplied shop to a bare
// *.myshopify.com host, tolerating a pasted URL/scheme/path. The result is safe
// to interpolate into Shopify endpoints — the app secret only ever leaves to a
// validated Shopify host.
func canonicalShopDomain(raw string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return "", fmt.Errorf("missing shop parameter (e.g. mystore.myshopify.com)")
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			s = u.Host
		}
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if !shopHostRe.MatchString(s) {
		return "", fmt.Errorf("invalid shop domain %q (must be a *.myshopify.com host)", raw)
	}
	return s, nil
}

func (p *ShopifyProvider) AuthURL(ctx context.Context, partnerID int64, params map[string]string) (string, error) {
	shop, err := canonicalShopDomain(params["shop"])
	if err != nil {
		return "", err
	}
	extra := map[string]string{"shop": shop}
	if e := params[StateEntityKey]; e != "" {
		extra[StateEntityKey] = e
	}
	state, err := p.Service.CreateOAuthState(ctx, partnerID, p.ProviderName, extra)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://%s/admin/oauth/authorize?client_id=%s&scope=%s&redirect_uri=%s&state=%s",
		shop,
		url.QueryEscape(p.APIKey),
		url.QueryEscape(p.Scopes),
		url.QueryEscape(p.CallbackURL),
		url.QueryEscape(state)), nil
}

// ValidateCallback is invoked by the OAuth-connect handler before Callback. It
// confirms the request genuinely came from Shopify (HMAC over the query, keyed
// by the app secret) and that the shop is a canonical Shopify host.
func (p *ShopifyProvider) ValidateCallback(ctx context.Context, query url.Values) error {
	if _, err := canonicalShopDomain(query.Get("shop")); err != nil {
		return err
	}
	apiSecret, err := p.Service.GetSecret(ctx, p.SecretName)
	if err != nil {
		return err
	}
	return validateShopifyHMAC(query, apiSecret)
}

// validateShopifyHMAC verifies Shopify's HMAC-SHA256 of the callback query: all
// params except hmac/signature, sorted by key, joined as key=value with '&',
// keyed by the app secret. Constant-time compare.
func validateShopifyHMAC(query url.Values, secret string) error {
	given := query.Get("hmac")
	if given == "" {
		return fmt.Errorf("missing hmac")
	}
	keys := make([]string, 0, len(query))
	for k := range query {
		if k == "hmac" || k == "signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var msg strings.Builder
	for i, k := range keys {
		if i > 0 {
			msg.WriteByte('&')
		}
		msg.WriteString(k)
		msg.WriteByte('=')
		msg.WriteString(query.Get(k))
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg.String()))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(given)) {
		return fmt.Errorf("shopify hmac validation failed")
	}
	return nil
}

func (p *ShopifyProvider) Callback(ctx context.Context, code, state string) error {
	partnerID, extra, err := p.Service.ConsumeOAuthState(ctx, state, p.ProviderName)
	if err != nil {
		return err
	}
	ctx = WithEntity(ctx, entityFromExtra(extra))
	shop, err := canonicalShopDomain(extra["shop"])
	if err != nil {
		return err
	}
	apiSecret, err := p.Service.GetSecret(ctx, p.SecretName)
	if err != nil {
		return err
	}
	tok, err := ManualTokenExchange(ctx, fmt.Sprintf("https://%s/admin/oauth/access_token", shop), url.Values{
		"client_id":     {p.APIKey},
		"client_secret": {apiSecret},
		"code":          {code},
	})
	if err != nil {
		return err
	}
	if tok.AccessToken == "" {
		return fmt.Errorf("no access token received")
	}
	// Confirm the merchant granted every required scope before storing the
	// connection active — a partial/tampered install must not be accepted and
	// then fail later.
	if err := requireScopes(tok.Scope, p.RequiredScopes); err != nil {
		return err
	}
	apiEndpoint := fmt.Sprintf("https://%s/admin/api/%s", shop, p.APIVersion)
	return p.Service.UpsertConnection(ctx, partnerID, p.ProviderName, ConnTypeOAuth, tok.AccessToken, apiEndpoint)
}

func requireScopes(granted string, required []string) error {
	g := make(map[string]bool)
	for _, s := range strings.Split(granted, ",") {
		if s = strings.TrimSpace(s); s != "" {
			g[s] = true
		}
	}
	for _, s := range required {
		if !g[s] {
			return fmt.Errorf("shopify did not grant required scope %q", s)
		}
	}
	return nil
}

// testHealthcheck calls /shop.json with Shopify's custom auth header.
func (p *ShopifyProvider) testHealthcheck(ctx context.Context, svc CredentialStore, partnerID int64, _, apiEndpoint string) error {
	credRef, _, err := svc.GetConnectionCredentials(ctx, partnerID, p.ProviderName)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiEndpoint+"/shop.json", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Shopify-Access-Token", credRef)
	return p.runHealthcheck(ctx, partnerID, req)
}
