package secret

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	infisical "github.com/infisical/go-sdk"
	infisicalerrors "github.com/infisical/go-sdk/packages/errors"
)

type infisicalClient interface {
	Secrets() infisical.SecretsInterface
}

type SecretProviderInfisical struct {
	client      infisicalClient
	projectID   string
	environment string
}

// NewSecretProviderInfisical opens an Infisical project environment on host. The machine-identity credentials come
// from INFISICAL_UNIVERSAL_AUTH_CLIENT_ID / _CLIENT_SECRET, read by the SDK,
// and the SDK keeps the login token refreshed.
func NewSecretProviderInfisical(ctx context.Context, projectID, environment, host string) (*SecretProviderInfisical, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("infisical secret provider: --infisical_project_id is required")
	}
	environment = strings.TrimSpace(environment)
	if environment == "" {
		return nil, fmt.Errorf("infisical secret provider: --infisical_environment is required")
	}

	client := infisical.NewInfisicalClient(ctx, infisical.Config{SiteUrl: strings.TrimSpace(host)})
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

// PutSecret updates the secret at the root path, creating it when the update
// answers 404.
func (s *SecretProviderInfisical) PutSecret(ctx context.Context, path string, value string) error {
	if err := validatePut(path, value); err != nil {
		return err
	}
	_, err := s.client.Secrets().Update(infisical.UpdateSecretOptions{
		SecretKey:      path,
		ProjectID:      s.projectID,
		Environment:    s.environment,
		SecretPath:     "/",
		NewSecretValue: value,
	})
	if apiErr, ok := errors.AsType[*infisicalerrors.APIError](err); ok && apiErr.StatusCode == http.StatusNotFound {
		_, err = s.client.Secrets().Create(infisical.CreateSecretOptions{
			SecretKey:   path,
			ProjectID:   s.projectID,
			Environment: s.environment,
			SecretPath:  "/",
			SecretValue: value,
		})
	}
	if err != nil {
		return fmt.Errorf("failed to put secret %s: %w", path, err)
	}
	return nil
}

var _ SecretRWProvider = (*SecretProviderInfisical)(nil)
