package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

type azureSecretsClient interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
}

type SecretProviderAzure struct {
	client azureSecretsClient
}

// NewSecretProviderAzure opens the Key Vault at vaultURL with
// azidentity.DefaultAzureCredential. Key Vault names hold letters, digits and
// dashes only, so the provider stores a name with each '_' as '-'.
func NewSecretProviderAzure(ctx context.Context, vaultURL string) (*SecretProviderAzure, error) {
	vaultURL = strings.TrimSpace(vaultURL)
	if vaultURL == "" {
		return nil, fmt.Errorf("azure secret provider: --azure_keyvault_url is required")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}
	return &SecretProviderAzure{client: client}, nil
}

// GetSecret reads the current version.
func (s *SecretProviderAzure) GetSecret(ctx context.Context, path string) (string, error) {
	resp, err := s.client.GetSecret(ctx, s.vaultName(path), "", nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", path, err)
	}
	if resp.Value == nil {
		return "", fmt.Errorf("secret %s has no value", path)
	}
	return strings.TrimSpace(*resp.Value), nil
}

// PutSecret relies on Key Vault's SetSecret being an upsert that adds a version.
func (s *SecretProviderAzure) PutSecret(ctx context.Context, path string, value string) error {
	if err := validatePut(path, value); err != nil {
		return err
	}
	if _, err := s.client.SetSecret(ctx, s.vaultName(path), azsecrets.SetSecretParameters{Value: &value}, nil); err != nil {
		return fmt.Errorf("failed to put secret %s: %w", path, err)
	}
	return nil
}

func (s *SecretProviderAzure) vaultName(path string) string {
	return strings.ReplaceAll(path, "_", "-")
}

var _ SecretRWProvider = (*SecretProviderAzure)(nil)
