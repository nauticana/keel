package secret

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type awsSecretsClient interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	CreateSecret(context.Context, *secretsmanager.CreateSecretInput, ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
}

type SecretProviderAWS struct {
	client awsSecretsClient
}

// NewSecretProviderAWS opens AWS Secrets Manager in region; an empty region
// takes the SDK's region chain, else us-east-1. AWS secrets are always regional.
func NewSecretProviderAWS(ctx context.Context, region string) (*SecretProviderAWS, error) {
	var opts []func(*config.LoadOptions) error
	if region = strings.TrimSpace(region); region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	return &SecretProviderAWS{client: secretsmanager.NewFromConfig(cfg)}, nil
}

// GetSecret fetches the named secret. Trims trailing whitespace
// (P1-27) so AWS, GSM, and local all return the same canonical
// string for the same secret value — operators frequently leave a
// trailing newline when typing values into a console form, and
// without the trim consumers get inconsistent length checks across
// providers.
func (s *SecretProviderAWS) GetSecret(ctx context.Context, path string) (string, error) {
	result, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &path,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", path, err)
	}
	if result.SecretString == nil {
		return "", fmt.Errorf("secret %s has no string value", path)
	}
	return strings.TrimSpace(*result.SecretString), nil
}

// PutSecret stores a new AWSCURRENT version, creating the secret when it does
// not exist yet.
func (s *SecretProviderAWS) PutSecret(ctx context.Context, path string, value string) error {
	if err := validatePut(path, value); err != nil {
		return err
	}
	putValue := func() error {
		_, err := s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: &path, SecretString: &value})
		return err
	}
	err := putValue()
	if _, ok := errors.AsType[*types.ResourceNotFoundException](err); ok {
		_, err = s.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: &path, SecretString: &value})
		if _, ok := errors.AsType[*types.ResourceExistsException](err); ok {
			err = putValue()
		}
	}
	if err != nil {
		return fmt.Errorf("failed to put secret %s: %w", path, err)
	}
	return nil
}

var _ SecretRWProvider = (*SecretProviderAWS)(nil)
