package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type SecretProviderGSM struct {
	client *secretmanager.Client
}

func NewSecretProviderGSM(ctx context.Context) (*SecretProviderGSM, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}
	return &SecretProviderGSM{client: client}, nil
}

func (s *SecretProviderGSM) GetSecret(ctx context.Context, path string) (string, error) {
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", *common.ProjectID, path)
	result, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		return "", fmt.Errorf("failed to access secret %s: %w", path, err)
	}
	return strings.TrimSpace(string(result.Payload.Data)), nil
}
