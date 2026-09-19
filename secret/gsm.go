package secret

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type gsmClient interface {
	AccessSecretVersion(context.Context, *secretmanagerpb.AccessSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	AddSecretVersion(context.Context, *secretmanagerpb.AddSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	CreateSecret(context.Context, *secretmanagerpb.CreateSecretRequest, ...gax.CallOption) (*secretmanagerpb.Secret, error)
}

type SecretProviderGSM struct {
	client gsmClient
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

// PutSecret adds a version, creating the secret with automatic replication when
// it does not exist yet.
func (s *SecretProviderGSM) PutSecret(ctx context.Context, path string, value string) error {
	if err := validatePut(path, value); err != nil {
		return err
	}
	project := "projects/" + *common.ProjectID
	addVersion := func() error {
		_, err := s.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
			Parent:  project + "/secrets/" + path,
			Payload: &secretmanagerpb.SecretPayload{Data: []byte(value)},
		})
		return err
	}
	err := addVersion()
	if status.Code(err) == codes.NotFound {
		_, err = s.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   project,
			SecretId: path,
			Secret: &secretmanagerpb.Secret{Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{Automatic: &secretmanagerpb.Replication_Automatic{}},
			}},
		})
		if err == nil || status.Code(err) == codes.AlreadyExists {
			err = addVersion()
		}
	}
	if err != nil {
		return fmt.Errorf("failed to put secret %s: %w", path, err)
	}
	return nil
}

var _ SecretRWProvider = (*SecretProviderGSM)(nil)
