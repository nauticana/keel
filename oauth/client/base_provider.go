package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"golang.org/x/oauth2"
)

// BaseProvider is the embeddable engine implementing the default oauth2-library
// flow. Concrete providers set its config; ones with a non-standard auth shape
// override AuthURL/Callback on the outer struct. Four optional hooks cover the
// common variations without subclassing:
//
//	DeriveAPIEndpoint — per-connection api_endpoint (e.g. GBP account name)
//	DeriveCredential  — map exchanged token → stored credential (Meta long-lived swap)
//	PostCallback      — extra writes after UpsertConnection
//	TestHealthcheck   — custom Test API call (Meta query-string auth)
type BaseProvider struct {
	Service      CredentialStore
	CallbackURL  string
	ProviderName string
	ConnType     string                   // defaults to ConnTypeOAuth
	Journal      logger.ApplicationLogger // optional; logs provider-side failures (e.g. GBP discovery 429/403) instead of swallowing them

	ClientID        string
	SecretName      string
	Endpoint        oauth2.Endpoint
	Scopes          []string
	AuthCodeOptions []oauth2.AuthCodeOption
	RequireRefresh  bool // fail Callback when the exchange returns no refresh token
	UsePKCE         bool // RFC 7636: engine handles the verifier/challenge (Twitter/X and any PKCE-required provider)

	APIEndpoint       string
	DeriveAPIEndpoint func(ctx context.Context, accessToken string) string
	DeriveCredential  func(ctx context.Context, t *oauth2.Token) (string, error)
	PostCallback      func(ctx context.Context, partnerID int64, t *oauth2.Token) error
	TestEndpoint      string // default Test does a bearer healthcheck here; empty = status-only
	TestHealthcheck   func(ctx context.Context, svc CredentialStore, partnerID int64, accessToken, apiEndpoint string) error
	SkipRefreshOnTest bool // long-lived-token providers (e.g. Meta) test the stored credential directly
}

var _ Provider = (*BaseProvider)(nil)

func (b *BaseProvider) connType() string {
	if b.ConnType == "" {
		return ConnTypeOAuth
	}
	return b.ConnType
}

func (b *BaseProvider) oauthConfig(ctx context.Context) (*oauth2.Config, error) {
	if b.ClientID == "" || b.SecretName == "" {
		return nil, fmt.Errorf("%s: missing ClientID or SecretName", b.ProviderName)
	}
	secret, err := b.Service.GetSecret(ctx, b.SecretName)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", b.SecretName, err)
	}
	return &oauth2.Config{
		ClientID:     b.ClientID,
		ClientSecret: secret,
		Endpoint:     b.Endpoint,
		RedirectURL:  b.CallbackURL,
		Scopes:       b.Scopes,
	}, nil
}

// AuthURL is the default oauth2-library consent URL builder. Providers with a
// custom URL shape (PKCE, client_key) override this on the outer struct. params
// (e.g. entity_id) ride the OAuth state across the redirect so Callback can
// recover them.
func (b *BaseProvider) AuthURL(ctx context.Context, partnerID int64, params map[string]string) (string, error) {
	cfg, err := b.oauthConfig(ctx)
	if err != nil {
		return "", err
	}
	opts := b.AuthCodeOptions
	if b.UsePKCE {
		verifier, challenge, err := GeneratePKCE()
		if err != nil {
			return "", err
		}
		// copy so we don't mutate the caller's map
		merged := make(map[string]string, len(params)+1)
		for k, v := range params {
			merged[k] = v
		}
		merged[StatePKCEKey] = verifier
		params = merged
		opts = append(append([]oauth2.AuthCodeOption{}, opts...),
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	state, err := b.Service.CreateOAuthState(ctx, partnerID, b.ProviderName, params)
	if err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state, opts...), nil
}

// Callback is the default exchange + persist flow. Providers with manual token
// exchanges override this on the outer struct.
func (b *BaseProvider) Callback(ctx context.Context, code, state string) error {
	cfg, err := b.oauthConfig(ctx)
	if err != nil {
		return err
	}
	// PKCE needs the verifier from state as an exchange param, so consume state
	// up front; the default flow consumes it after exchange.
	var (
		partnerID    int64
		extra        map[string]string
		exchangeOpts []oauth2.AuthCodeOption
	)
	if b.UsePKCE {
		partnerID, extra, err = b.Service.ConsumeOAuthState(ctx, state, b.ProviderName)
		if err != nil {
			return err
		}
		verifier := extra[StatePKCEKey]
		if verifier == "" {
			return fmt.Errorf("%s: PKCE verifier missing from state", b.ProviderName)
		}
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("code_verifier", verifier))
	}
	token, err := cfg.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return fmt.Errorf("token exchange: %w", err)
	}
	if b.RequireRefresh && token.RefreshToken == "" {
		return fmt.Errorf("%s: no refresh token; re-authorize with prompt=consent", b.ProviderName)
	}
	if !b.UsePKCE {
		partnerID, extra, err = b.Service.ConsumeOAuthState(ctx, state, b.ProviderName)
		if err != nil {
			return err
		}
	}
	// Recover the entity scope stashed at AuthURL so the store writes the right
	// (partner, entity) row; 0 = tenant-wide for callers that never set it.
	ctx = WithEntity(ctx, entityFromExtra(extra))
	credRef, err := b.deriveCredential(ctx, token)
	if err != nil {
		return err
	}
	apiEndpoint := b.APIEndpoint
	if b.DeriveAPIEndpoint != nil {
		apiEndpoint = b.DeriveAPIEndpoint(ctx, token.AccessToken)
	}
	if err := b.Service.UpsertConnection(ctx, partnerID, b.ProviderName, b.connType(), credRef, apiEndpoint); err != nil {
		return err
	}
	if b.PostCallback != nil {
		return b.PostCallback(ctx, partnerID, token)
	}
	return nil
}

// deriveCredential returns the value stored as the connection credential.
// Hook-overridable; default prefers the refresh token, falling back to access.
func (b *BaseProvider) deriveCredential(ctx context.Context, t *oauth2.Token) (string, error) {
	if b.DeriveCredential != nil {
		return b.DeriveCredential(ctx, t)
	}
	if t.RefreshToken != "" {
		return t.RefreshToken, nil
	}
	return t.AccessToken, nil
}

// Test refreshes the stored credential and optionally hits an API endpoint to
// confirm the resulting access token works, recording the outcome as the
// connection status.
func (b *BaseProvider) Test(ctx context.Context, partnerID int64) error {
	credRef, apiEndpoint, err := b.Service.GetConnectionCredentials(ctx, partnerID, b.ProviderName)
	if err != nil {
		return err
	}
	accessToken := credRef
	if !b.SkipRefreshOnTest {
		if accessToken, err = b.Service.RefreshAccessToken(ctx, partnerID, b.ProviderName); err != nil {
			return err
		}
	}
	switch {
	case b.TestHealthcheck != nil:
		return b.TestHealthcheck(ctx, b.Service, partnerID, accessToken, apiEndpoint)
	case b.TestEndpoint != "":
		return b.bearerHealthcheck(ctx, partnerID, accessToken)
	default:
		return b.Service.UpdateConnectionStatus(ctx, partnerID, b.ProviderName, b.connType(), ConnStatusActive)
	}
}

// bearerHealthcheck GETs TestEndpoint with a bearer token and records the
// resulting connection status.
func (b *BaseProvider) bearerHealthcheck(ctx context.Context, partnerID int64, accessToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.TestEndpoint, nil)
	if err != nil {
		return fmt.Errorf("build healthcheck request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return b.runHealthcheck(ctx, partnerID, req)
}

// runHealthcheck executes req and maps the outcome to a connection status
// (Active on 2xx/3xx, Error otherwise or on transport failure). Providers with a
// non-bearer auth scheme (Shopify header, Meta query string) build req then call
// this to record the result.
func (b *BaseProvider) runHealthcheck(ctx context.Context, partnerID int64, req *http.Request) error {
	resp, err := common.HTTPClient().Do(req)
	if err != nil {
		_ = b.Service.UpdateConnectionStatus(ctx, partnerID, b.ProviderName, b.connType(), ConnStatusError)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		_ = b.Service.UpdateConnectionStatus(ctx, partnerID, b.ProviderName, b.connType(), ConnStatusError)
		return fmt.Errorf("%s API returned HTTP %d", b.ProviderName, resp.StatusCode)
	}
	return b.Service.UpdateConnectionStatus(ctx, partnerID, b.ProviderName, b.connType(), ConnStatusActive)
}
