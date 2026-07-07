package oauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/oauth/authserver"
	"github.com/nauticana/keel/oauth/resource"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

// Setup is the wired OAuth result selected by oauth_as_mode. AS is nil in
// external/disabled modes; Validator is nil only when disabled. Mount AS with
// handler.OAuthASHandler and wrap protected routes with the Validator via
// resource.Middleware.
type Setup struct {
	Mode      string
	AS        port.AuthorizationServer
	Validator port.TokenValidator
	Signer    *authserver.RS256Signer
}

// NewOAuthFromConfig wires OAuth from the --oauth_* flags:
//   - disabled: nothing.
//   - external: keel is resource-server only; validates the oauth_issuer IdP.
//   - local (default): keel is its own AS, issuing + validating RS256 tokens.
func NewOAuthFromConfig(ctx context.Context, db port.DatabaseRepository, secrets secret.SecretProvider, httpc *http.Client, journal logger.ApplicationLogger) (*Setup, error) {
	mode := common.Config().OAuthASMode
	switch mode {
	case "disabled":
		return &Setup{Mode: mode}, nil

	case "external":
		v, err := resource.NewJWTValidatorFromConfig(httpc)
		if err != nil {
			return nil, err
		}
		// NewJWTValidatorFromConfig returns nil when oauth_issuer is empty; in
		// external mode that leaves nothing to validate against, so fail fast here
		// rather than panic later in resource.Middleware (which rejects a nil validator).
		if v == nil {
			return nil, fmt.Errorf("oauth: oauth_as_mode=external requires oauth_issuer (the external IdP to validate tokens against)")
		}
		return &Setup{Mode: mode, Validator: v}, nil

	case "local":
		issuer := common.Config().OAuthIssuer
		if issuer == "" {
			return nil, fmt.Errorf("oauth: oauth_as_mode=local requires oauth_issuer (this AS's public base URL)")
		}
		// An empty scope allowlist would let open DCR register + mint any scope
		// (e.g. admin). Require an explicit list so the clamp has teeth.
		if len(common.SplitCSV(common.Config().OAuthScopesSupported)) == 0 {
			return nil, fmt.Errorf("oauth: oauth_as_mode=local requires a non-empty oauth_scopes_supported (the scope allowlist)")
		}
		signer, err := loadOrGenSigner(ctx, secrets, journal)
		if err != nil {
			return nil, err
		}
		aud := common.Config().OAuthAudience
		if aud == "" {
			aud = issuer
		}
		clients := &authserver.ClientStoreDB{DB: db}
		clients.Init(ctx)
		codes := &authserver.CodeStoreDB{DB: db}
		codes.Init(ctx)
		tokens := &authserver.TokenStoreDB{DB: db}
		tokens.Init(ctx)
		validator := authserver.NewLocalValidator(signer, issuer, aud)
		// Valid token audiences = the multi-resource CSV plus the single PRM
		// resource; DefaultAudience is always added in authserver.NewLocal.
		resources := common.SplitCSV(common.Config().OAuthResources)
		if common.Config().OAuthResource != "" {
			resources = append(resources, common.Config().OAuthResource)
		}
		cfg := authserver.Config{
			Issuer:          issuer,
			DefaultAudience: aud,
			Scopes:          common.SplitCSV(common.Config().OAuthScopesSupported),
			Resources:       resources,
			AccessTTL:       common.Config().OAuthAccessTokenTTL,
			RefreshTTL:      common.Config().OAuthRefreshTokenTTL,
			CodeTTL:         common.Config().OAuthCodeTTL,
		}
		as := authserver.NewLocal(signer, clients, codes, tokens, cfg)
		// validator is the single-audience resource-server validator for the
		// caller's resource.Middleware; the AS builds its own multi-audience
		// validator internally for introspection / token-exchange.
		return &Setup{Mode: mode, AS: as, Validator: validator, Signer: signer}, nil

	default:
		return nil, fmt.Errorf("oauth: unknown oauth_as_mode %q (want local|external|disabled)", mode)
	}
}

func loadOrGenSigner(ctx context.Context, secrets secret.SecretProvider, journal logger.ApplicationLogger) (*authserver.RS256Signer, error) {
	name := common.Config().OAuthSigningKeySecret
	if name == "" {
		if journal != nil {
			journal.Error("oauth: oauth_signing_key_secret empty — using an EPHEMERAL signing key; tokens die on restart and differ per node (dev only)")
		}
		return authserver.NewEphemeralRS256Signer()
	}
	pem, err := secrets.GetSecret(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("oauth: load signing key %q: %w", name, err)
	}
	return authserver.NewRS256Signer(pem)
}
