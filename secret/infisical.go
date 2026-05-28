package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"

	infisical "github.com/infisical/go-sdk"
)

type SecretProviderInfisical struct {
	client      infisical.InfisicalClientInterface
	projectID   string
	environment string
}

// NewSecretProviderInfisical constructs the Infisical backend, the
// production-grade managed-secrets option for deployments not on
// AWS/GCP/Azure (which would otherwise fall back to the local
// secrets.json file).
//
// Project id, environment slug, and host are the non-secret location
// knobs (flags); the machine-identity client id/secret are read by the
// SDK from INFISICAL_UNIVERSAL_AUTH_CLIENT_ID / _CLIENT_SECRET when
// UniversalAuthLogin is called with empty args. This mirrors how the
// GSM/AWS/Azure backends defer to their vendor SDK's ambient credential
// chain — no secret material is passed through keel's own flags.
//
// AutoTokenRefresh (the SDK default) keeps the universal-auth token
// renewed for the process lifetime; the factory builds this once at
// boot, identical to the other cloud backends.
//
// Empty --infisical_project_id or --infisical_environment is a
// configuration error rather than a silent default, matching the
// fail-fast behavior of the AWS and Azure providers.
func NewSecretProviderInfisical(ctx context.Context) (*SecretProviderInfisical, error) {
	projectID := strings.TrimSpace(*common.InfisicalProjectID)
	if projectID == "" {
		return nil, fmt.Errorf("infisical secret provider: --infisical_project_id is required")
	}
	environment := strings.TrimSpace(*common.InfisicalEnvironment)
	if environment == "" {
		return nil, fmt.Errorf("infisical secret provider: --infisical_environment is required")
	}

	client := infisical.NewInfisicalClient(ctx, infisical.Config{
		SiteUrl:          strings.TrimSpace(*common.InfisicalHost),
		AutoTokenRefresh: true,
	})
	// Empty args => SDK reads INFISICAL_UNIVERSAL_AUTH_CLIENT_ID/_SECRET
	// from the environment (the ambient-credential analog of GSM's ADC).
	if _, err := client.Auth().UniversalAuthLogin("", ""); err != nil {
		return nil, fmt.Errorf("infisical universal-auth login failed: %w", err)
	}

	return &SecretProviderInfisical{
		client:      client,
		projectID:   projectID,
		environment: environment,
	}, nil
}

// GetSecret fetches the named secret from the configured project +
// environment at the root path. Trims trailing whitespace (P1-27) so
// Infisical, Azure, AWS, GSM and local all return the same canonical
// string for the same secret value.
func (s *SecretProviderInfisical) GetSecret(ctx context.Context, path string) (string, error) {
	secret, err := s.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretKey:   path,
		ProjectID:   s.projectID,
		Environment: s.environment,
		SecretPath:  "/",
	})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", path, err)
	}
	return strings.TrimSpace(secret.SecretValue), nil
}
