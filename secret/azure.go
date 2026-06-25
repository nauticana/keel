package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

type SecretProviderAzure struct {
	client *azsecrets.Client
}

// NewSecretProviderAzure constructs the Azure Key Vault backend.
//
// The vault endpoint comes from the dedicated --azure_keyvault_url flag.
// Authentication uses azidentity.DefaultAzureCredential — identical to
// the chain in storage/azure.go — so a managed identity (Azure VM / AKS)
// or the standard AZURE_* environment fallback is honored without any
// secret material being passed through this process's own config.
//
// Empty --azure_keyvault_url is a configuration error rather than a
// silent default: there is no sensible vault to guess, and falling
// through to an unrelated vault would surface as cryptic 404s on the
// first GetSecret instead of a clear boot-time failure.
func NewSecretProviderAzure(ctx context.Context) (*SecretProviderAzure, error) {
	vaultURL := strings.TrimSpace(*common.AzureKeyVaultURL)
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

// GetSecret fetches the latest version of the named secret. The empty
// version string asks Key Vault for the current version, matching the
// "latest"-style semantics of the GSM backend.
//
// Trims trailing whitespace (P1-27) so Azure, AWS, GSM, and local all
// return the same canonical string for the same secret value.
func (s *SecretProviderAzure) GetSecret(ctx context.Context, path string) (string, error) {
	resp, err := s.client.GetSecret(ctx, path, "", nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", path, err)
	}
	if resp.Value == nil {
		return "", fmt.Errorf("secret %s has no value", path)
	}
	return strings.TrimSpace(*resp.Value), nil
}

var _ SecretProvider = (*SecretProviderAzure)(nil)
