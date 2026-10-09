package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/oauth/client"
	"github.com/nauticana/keel/port"
)

// Client signs users in with one OpenID Provider by the authorization-code
// flow with PKCE and a nonce. It is usable on its own, for an application
// with one fixed identity provider, or built per connection by Provider.
type Client struct {
	Issuer       string
	DiscoveryURL string
	ClientID     string
	Credential   ClientCredential
	Scopes       []string      // openid is always requested
	SubjectClaim string        // empty = sub
	EmailClaim   string        // empty = email
	HTTP         *http.Client  // nil = common.PublicHTTPClient()
	MetadataTTL  time.Duration // 0 = social_jwks_cache_ttl

	mu      sync.Mutex
	meta    *Discovery
	keys    *crypto.JWKSProvider
	fetched time.Time
}

type pending struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Token    bool   `json:"t,omitempty"`
}

// Begin builds the authorization request. The caller stores Pending with the
// state and passes both back to Complete.
func (c *Client) Begin(ctx context.Context, req port.IdentityBegin) (*port.IdentityRedirect, error) {
	if req.State == "" || req.RedirectURI == "" {
		return nil, fmt.Errorf("%w: state and redirect URI are required", ErrBadConfiguration)
	}
	meta, _, err := c.metadata(ctx)
	if err != nil {
		return nil, err
	}
	if !meta.supportsAuth(c.Credential.Method) {
		return nil, fmt.Errorf("%w: the issuer does not accept %s", ErrBadConfiguration, c.Credential.Method)
	}
	nonce, err := randomToken()
	if err != nil {
		return nil, err
	}
	verifier, challenge, err := client.GeneratePKCE()
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {req.RedirectURI},
		"scope":                 {strings.Join(c.scopes(req.Scopes), " ")},
		"state":                 {req.State},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if req.LoginHint != "" {
		q.Set("login_hint", req.LoginHint)
	}
	p, err := json.Marshal(pending{State: req.State, Nonce: nonce, Verifier: verifier, Token: len(req.Scopes) > 0})
	if err != nil {
		return nil, err
	}
	sep := "?"
	if strings.Contains(meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return &port.IdentityRedirect{URL: meta.AuthorizationEndpoint + sep + q.Encode(), Pending: string(p)}, nil
}

// Complete redeems the callback's code and verifies the ID token: issuer,
// sole audience and azp, expiry, nonce, and a signature
// by an algorithm both keel and the issuer accept.
func (c *Client) Complete(ctx context.Context, cb port.IdentityCallback) (*port.IdentityAssertion, error) {
	var p pending
	if err := json.Unmarshal([]byte(cb.Pending), &p); err != nil || p.State == "" || p.Nonce == "" || p.Verifier == "" {
		return nil, fmt.Errorf("%w: pending sign-in", ErrInvalidResponse)
	}
	if subtle.ConstantTimeCompare([]byte(cb.Params.Get("state")), []byte(p.State)) != 1 {
		return nil, fmt.Errorf("%w: state", ErrInvalidResponse)
	}
	if code := cb.Params.Get("error"); code != "" {
		return nil, &CallbackError{Code: code}
	}
	code := cb.Params.Get("code")
	if code == "" || cb.RedirectURI == "" {
		return nil, fmt.Errorf("%w: code and redirect URI are required", ErrInvalidResponse)
	}
	meta, keys, err := c.metadata(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cb.RedirectURI},
		"code_verifier": {p.Verifier},
	}
	set, err := exchangeCode(ctx, c.httpClient(), meta.TokenEndpoint, c.ClientID, c.Credential, form)
	if err != nil {
		return nil, err
	}
	if set.IDToken == "" {
		return nil, fmt.Errorf("%w: no id_token", ErrInvalidResponse)
	}
	claims, err := crypto.VerifyAsymmetric(ctx, keys, set.IDToken, c.ClientID, c.Issuer, meta.SigningAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("%w: id_token: %v", ErrInvalidResponse, err)
	}
	if err := checkAudience(claims, c.ClientID); err != nil {
		return nil, err
	}
	if !nonceMatches(claims, p.Nonce) {
		return nil, fmt.Errorf("%w: nonce", ErrInvalidResponse)
	}
	a, err := assertionFromClaims(c.Issuer, claims, c.SubjectClaim, c.EmailClaim)
	if err != nil {
		return nil, err
	}
	if p.Token {
		a.AccessToken = set.AccessToken
	}
	return a, nil
}

func (c *Client) scopes(extra []string) []string {
	out := []string{"openid"}
	for _, s := range append(slices.Clone(c.Scopes), extra...) {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return common.PublicHTTPClient()
}

// metadata returns the discovery document and key set, refreshing after
// MetadataTTL; an unreachable issuer is served stale up to sso_metadata_max_stale.
func (c *Client) metadata(ctx context.Context) (*Discovery, *crypto.JWKSProvider, error) {
	ttl := c.MetadataTTL
	if ttl <= 0 {
		ttl = config.Config().SocialJWKSCacheTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	age := time.Since(c.fetched)
	if c.meta != nil && age < ttl {
		return c.meta, c.keys, nil
	}
	meta, err := FetchDiscovery(ctx, c.httpClient(), c.DiscoveryURL, c.Issuer)
	if err != nil {
		if c.meta != nil && age < config.Config().SSOMetadataMaxStale {
			return c.meta, c.keys, nil
		}
		return nil, nil, err
	}
	if c.keys == nil || c.meta.JWKSURI != meta.JWKSURI {
		c.keys = crypto.NewJWKSProvider(meta.JWKSURI, ttl, c.httpClient())
	}
	c.meta, c.fetched = meta, time.Now()
	return c.meta, c.keys, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
