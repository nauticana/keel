package secret

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
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
	parent string // projects/P or projects/P/locations/R
}

// NewSecretProviderGSM opens the project's global secrets, or its regional
// secrets in region when one is given.
func NewSecretProviderGSM(ctx context.Context, projectID, region string) (*SecretProviderGSM, error) {
	projectID, region = strings.TrimSpace(projectID), strings.TrimSpace(region)
	if projectID == "" {
		return nil, fmt.Errorf("gsm secret provider: --gcp_project_id is required")
	}
	parent := "projects/" + projectID
	var opts []option.ClientOption
	if region != "" {
		parent += "/locations/" + region
		opts = append(opts, option.WithEndpoint("secretmanager."+region+".rep.googleapis.com:443"))
	}
	client, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}
	return &SecretProviderGSM{client: client, parent: parent}, nil
}

func (s *SecretProviderGSM) regional() bool { return strings.Contains(s.parent, "/locations/") }

func (s *SecretProviderGSM) GetSecret(ctx context.Context, path string) (string, error) {
	name := s.parent + "/secrets/" + path + "/versions/latest"
	result, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		return "", fmt.Errorf("failed to access secret %s: %w", path, err)
	}
	return strings.TrimSpace(string(result.Payload.Data)), nil
}

// PutSecret adds a version, creating the secret when it does not exist yet: a
// global secret with automatic replication, a regional one in its region.
func (s *SecretProviderGSM) PutSecret(ctx context.Context, path string, value string) error {
	if err := validatePut(path, value); err != nil {
		return err
	}
	addVersion := func() error {
		_, err := s.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
			Parent:  s.parent + "/secrets/" + path,
			Payload: &secretmanagerpb.SecretPayload{Data: []byte(value)},
		})
		return err
	}
	err := addVersion()
	if status.Code(err) == codes.NotFound {
		secret := &secretmanagerpb.Secret{}
		if !s.regional() {
			secret.Replication = &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{Automatic: &secretmanagerpb.Replication_Automatic{}},
			}
		}
		_, err = s.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{Parent: s.parent, SecretId: path, Secret: secret})
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
