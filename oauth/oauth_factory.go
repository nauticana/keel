package oauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

// OAuthSetup is the wired OAuth result selected by --oauth_as_mode. AS is nil in
// external/disabled modes; Validator is nil only when disabled. Mount AS with
// handler.OAuthASHandler and wrap protected routes with the Validator via
// OAuthResourceMiddleware.
type OAuthSetup struct {
	Mode      string
	AS        port.AuthorizationServer
	Validator port.TokenValidator
	Signer    *RS256Signer
}

// NewOAuthFromFlags wires OAuth from the --oauth_* flags:
//   - disabled: nothing.
//   - external: keel is resource-server only; validates the --oauth_issuer IdP.
//   - local (default): keel is its own AS, issuing + validating RS256 tokens.
func NewOAuthFromFlags(ctx context.Context, db data.DatabaseRepository, secrets secret.SecretProvider, httpc *http.Client, journal logger.ApplicationLogger) (*OAuthSetup, error) {
	mode := *common.OAuthASMode
	switch mode {
	case "disabled":
		return &OAuthSetup{Mode: mode}, nil

	case "external":
		v, err := NewJWTValidatorFromFlags(httpc)
		if err != nil {
			return nil, err
		}
		return &OAuthSetup{Mode: mode, Validator: v}, nil

	case "local":
		issuer := *common.OAuthIssuer
		if issuer == "" {
			return nil, fmt.Errorf("oauth: --oauth_as_mode=local requires --oauth_issuer (this AS's public base URL)")
		}
		// An empty scope allowlist would let open DCR register + mint any scope
		// (e.g. admin). Require an explicit list so the clamp has teeth.
		if len(common.SplitCSV(*common.OAuthScopesSupported)) == 0 {
			return nil, fmt.Errorf("oauth: --oauth_as_mode=local requires a non-empty --oauth_scopes_supported (the scope allowlist)")
		}
		signer, err := loadOrGenSigner(ctx, secrets, journal)
		if err != nil {
			return nil, err
		}
		aud := *common.OAuthAudience
		if aud == "" {
			aud = issuer
		}
		clients := &OAuthClientStoreDB{DB: db}
		clients.Init(ctx)
		codes := &AuthCodeStoreDB{DB: db}
		codes.Init(ctx)
		tokens := &OAuthTokenStoreDB{DB: db}
		tokens.Init(ctx)
		validator := NewLocalJWTValidator(signer, issuer, aud)
		// Valid token audiences = the multi-resource CSV plus the single PRM
		// resource; DefaultAudience is always added in NewAuthorizationServerLocal.
		resources := common.SplitCSV(*common.OAuthResources)
		if *common.OAuthResource != "" {
			resources = append(resources, *common.OAuthResource)
		}
		cfg := OAuthASConfig{
			Issuer:          issuer,
			DefaultAudience: aud,
			Scopes:          common.SplitCSV(*common.OAuthScopesSupported),
			Resources:       resources,
			AccessTTL:       *common.OAuthAccessTokenTTL,
			RefreshTTL:      *common.OAuthRefreshTokenTTL,
			CodeTTL:         *common.OAuthCodeTTL,
		}
		as := NewAuthorizationServerLocal(signer, clients, codes, tokens, cfg)
		// validator is the single-audience resource-server validator for the
		// caller's OAuthResourceMiddleware; the AS builds its own multi-audience
		// validator internally for introspection / token-exchange.
		return &OAuthSetup{Mode: mode, AS: as, Validator: validator, Signer: signer}, nil

	default:
		return nil, fmt.Errorf("oauth: unknown --oauth_as_mode %q (want local|external|disabled)", mode)
	}
}

func loadOrGenSigner(ctx context.Context, secrets secret.SecretProvider, journal logger.ApplicationLogger) (*RS256Signer, error) {
	name := *common.OAuthSigningKeySecret
	if name == "" {
		if journal != nil {
			journal.Error("oauth: --oauth_signing_key_secret empty — using an EPHEMERAL signing key; tokens die on restart and differ per node (dev only)")
		}
		return NewEphemeralRS256Signer()
	}
	pem, err := secrets.GetSecret(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("oauth: load signing key %q: %w", name, err)
	}
	return NewRS256Signer(pem)
}
