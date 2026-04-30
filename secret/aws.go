package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SecretProviderAWS struct {
	client *secretsmanager.Client
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
