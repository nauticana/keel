package secret

import (
	"context"
	"fmt"
	"log"

	"github.com/nauticana/keel/common"
)

// NewSecretProvider opens the store the bootstrap flags select.
func NewSecretProvider(ctx context.Context) (SecretProvider, error) {
	return NewSecretRWProvider(ctx)
}

// NewSecretRWProvider is for the few components that mint or rotate secrets;
// everything else takes the read-only SecretProvider.
func NewSecretRWProvider(ctx context.Context) (SecretRWProvider, error) {
	return NewSecretProviderFor(ctx, Settings{
		Mode:                 *common.SecretMode,
		Keystore:             *common.Keystore,
		GCPProjectID:         *common.ProjectID,
		GCPSecretRegion:      *common.GCPSecretRegion,
		AWSRegion:            *common.AWSRegion,
		AzureKeyVaultURL:     *common.AzureKeyVaultURL,
		InfisicalProjectID:   *common.InfisicalProjectID,
		InfisicalEnvironment: *common.InfisicalEnvironment,
		InfisicalHost:        *common.InfisicalHost,
	})
}

// NewSecretProviderFor opens the store s selects, independent of the flags.
func NewSecretProviderFor(ctx context.Context, s Settings) (SecretRWProvider, error) {
	switch s.Mode {
	case "local":
		return &SecretProviderLocal{Filename: s.Keystore}, nil
	case "gsm":
		return NewSecretProviderGSM(ctx, s.GCPProjectID, s.GCPSecretRegion)
	case "aws":
		return NewSecretProviderAWS(ctx, s.AWSRegion)
	case "azure":
		return NewSecretProviderAzure(ctx, s.AzureKeyVaultURL)
	case "infisical":
		return NewSecretProviderInfisical(ctx, s.InfisicalProjectID, s.InfisicalEnvironment, s.InfisicalHost)
	default:
		return nil, fmt.Errorf("unknown secret_mode: %s", s.Mode)
	}
}

// MustGet returns the named secret or terminates the process. Use it only at
// boot for required keys; never on a request path.
func MustGet(ctx context.Context, p SecretProvider, name string) string {
	v, err := p.GetSecret(ctx, name)
	if err != nil {
		log.Fatalf("secret %q: %v", name, err)
	}
	return v
}
