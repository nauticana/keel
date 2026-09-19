package secret

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"

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

// NewSecretProviderAWS constructs the AWS Secrets Manager backend.
//
// The region comes from the dedicated --aws_region flag (P1-26).
// The previous implementation read --keystore here, overloading a
// single flag as both "local JSON path" and "AWS region" — a footgun
// that produced cryptic SDK errors when an operator copied a
// keystore-path config into an AWS deployment.
func NewSecretProviderAWS(ctx context.Context) (*SecretProviderAWS, error) {
	region := strings.TrimSpace(*common.AWSRegion)
	if region == "" {
		return nil, fmt.Errorf("aws secret provider: --aws_region is required")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
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
	var notFound *types.ResourceNotFoundException
	if errors.As(err, &notFound) {
		_, err = s.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: &path, SecretString: &value})
		var exists *types.ResourceExistsException
		if errors.As(err, &exists) {
			err = putValue()
		}
	}
	if err != nil {
		return fmt.Errorf("failed to put secret %s: %w", path, err)
	}
	return nil
}

var _ SecretRWProvider = (*SecretProviderAWS)(nil)
