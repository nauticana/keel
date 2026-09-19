package secret

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/googleapis/gax-go/v2"
	infisical "github.com/infisical/go-sdk"
	infisicalerrors "github.com/infisical/go-sdk/packages/errors"
	"github.com/infisical/go-sdk/packages/models"
	"github.com/nauticana/keel/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ctx = context.Background()

func TestPutSecret_RejectsBlankPathOrValue(t *testing.T) {
	providers := map[string]SecretRWProvider{
		"local":     &SecretProviderLocal{Filename: filepath.Join(t.TempDir(), "secrets.json")},
		"gsm":       &SecretProviderGSM{client: &fakeGSM{}},
		"aws":       &SecretProviderAWS{client: &fakeAWS{}},
		"azure":     &SecretProviderAzure{client: &fakeAzure{}},
		"infisical": &SecretProviderInfisical{client: &fakeInfisical{}},
	}
	for name, p := range providers {
		if err := p.PutSecret(ctx, " ", "v"); !errors.Is(err, ErrInvalidSecretWrite) {
			t.Errorf("%s blank path: %v, want ErrInvalidSecretWrite", name, err)
		}
		if err := p.PutSecret(ctx, "k", " \n"); !errors.Is(err, ErrInvalidSecretWrite) {
			t.Errorf("%s blank value: %v, want ErrInvalidSecretWrite", name, err)
		}
	}
}

func TestLocalPutSecret_CreatesOwnerOnlyFileAndReadsBack(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secrets.json")
	p := &SecretProviderLocal{Filename: file}
	if _, err := p.GetSecret(ctx, "k"); err == nil {
		t.Fatal("missing file must fail the read")
	}
	if err := p.PutSecret(ctx, "k", "v1\n"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if got, err := p.GetSecret(ctx, "k"); err != nil || got != "v1" {
		t.Fatalf("GetSecret = %q, %v; want trimmed v1", got, err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("file mode %#o, want 0600", mode)
	}
	if got, _ := (&SecretProviderLocal{Filename: file}).GetSecret(ctx, "k"); got != "v1" {
		t.Fatalf("a fresh provider read %q, want v1", got)
	}
}

func TestLocalPutSecret_KeepsKeysAddedOnDiskSinceLoad(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(file, []byte(`{"a":"1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	p := &SecretProviderLocal{Filename: file}
	if _, err := p.GetSecret(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{"a":"1","operator":"added"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.PutSecret(ctx, "a", "2"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	for key, want := range map[string]string{"a": "2", "operator": "added"} {
		if got, err := p.GetSecret(ctx, key); err != nil || got != want {
			t.Errorf("GetSecret(%q) = %q, %v; want %q", key, got, err, want)
		}
	}
	leftovers, _ := filepath.Glob(file + ".*.tmp")
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

func TestLocalPutSecret_RefusesToOverwriteUnparseableFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(file, []byte(`{broken`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&SecretProviderLocal{Filename: file}).PutSecret(ctx, "k", "v"); err == nil {
		t.Fatal("PutSecret replaced a file it could not parse")
	}
	if data, _ := os.ReadFile(file); string(data) != `{broken` {
		t.Fatalf("file was modified: %q", data)
	}
}

type fakeGSM struct {
	secrets       map[string][]string
	createErr     error
	createdBehind bool // another writer creates the secret between our two calls
}

func (f *fakeGSM) AccessSecretVersion(context.Context, *secretmanagerpb.AccessSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return nil, errors.New("unused")
}

func (f *fakeGSM) AddSecretVersion(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	if _, ok := f.secrets[req.Parent]; !ok {
		return nil, status.Error(codes.NotFound, "no such secret")
	}
	f.secrets[req.Parent] = append(f.secrets[req.Parent], string(req.Payload.Data))
	return &secretmanagerpb.SecretVersion{}, nil
}

func (f *fakeGSM) CreateSecret(_ context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	name := req.Parent + "/secrets/" + req.SecretId
	if f.secrets == nil {
		f.secrets = map[string][]string{}
	}
	f.secrets[name] = nil
	if f.createdBehind {
		return nil, status.Error(codes.AlreadyExists, "exists")
	}
	if req.Secret.GetReplication().GetAutomatic() == nil {
		return nil, status.Error(codes.InvalidArgument, "replication required")
	}
	return &secretmanagerpb.Secret{}, nil
}

func TestGSMPutSecret(t *testing.T) {
	name := "projects/" + *common.ProjectID + "/secrets/k"

	existing := &fakeGSM{secrets: map[string][]string{name: {"old"}}}
	if err := (&SecretProviderGSM{client: existing}).PutSecret(ctx, "k", "new"); err != nil {
		t.Fatalf("existing secret: %v", err)
	}
	if got := existing.secrets[name]; len(got) != 2 || got[1] != "new" {
		t.Fatalf("versions = %v, want a second version", got)
	}

	for label, fake := range map[string]*fakeGSM{"missing": {}, "lost create race": {createdBehind: true}} {
		if err := (&SecretProviderGSM{client: fake}).PutSecret(ctx, "k", "v"); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got := fake.secrets[name]; len(got) != 1 || got[0] != "v" {
			t.Fatalf("%s: versions = %v, want [v]", label, got)
		}
	}

	denied := &fakeGSM{createErr: status.Error(codes.PermissionDenied, "no secrets.create")}
	if err := (&SecretProviderGSM{client: denied}).PutSecret(ctx, "k", "v"); status.Code(errors.Unwrap(err)) != codes.PermissionDenied {
		t.Fatalf("create failure must surface, got %v", err)
	}
}

type fakeAWS struct {
	secrets       map[string]string
	createdBehind bool
}

func (f *fakeAWS) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return nil, errors.New("unused")
}

func (f *fakeAWS) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	if _, ok := f.secrets[*in.SecretId]; !ok {
		return nil, &types.ResourceNotFoundException{}
	}
	f.secrets[*in.SecretId] = *in.SecretString
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func (f *fakeAWS) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	if f.secrets == nil {
		f.secrets = map[string]string{}
	}
	if f.createdBehind {
		f.secrets[*in.Name] = "someone else's value"
		return nil, &types.ResourceExistsException{}
	}
	f.secrets[*in.Name] = *in.SecretString
	return &secretsmanager.CreateSecretOutput{}, nil
}

func TestAWSPutSecret(t *testing.T) {
	for label, fake := range map[string]*fakeAWS{
		"existing":         {secrets: map[string]string{"k": "old"}},
		"missing":          {},
		"lost create race": {createdBehind: true},
	} {
		if err := (&SecretProviderAWS{client: fake}).PutSecret(ctx, "k", "new"); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if fake.secrets["k"] != "new" {
			t.Fatalf("%s: stored %q, want new", label, fake.secrets["k"])
		}
	}
}

type fakeAzure struct {
	secrets map[string]string
	err     error
}

func (f *fakeAzure) GetSecret(context.Context, string, string, *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return azsecrets.GetSecretResponse{}, errors.New("unused")
}

func (f *fakeAzure) SetSecret(_ context.Context, name string, p azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	if f.err != nil {
		return azsecrets.SetSecretResponse{}, f.err
	}
	if f.secrets == nil {
		f.secrets = map[string]string{}
	}
	f.secrets[name] = *p.Value
	return azsecrets.SetSecretResponse{}, nil
}

func TestAzurePutSecret(t *testing.T) {
	fake := &fakeAzure{}
	if err := (&SecretProviderAzure{client: fake}).PutSecret(ctx, "k", "v"); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if fake.secrets["k"] != "v" {
		t.Fatalf("stored %q, want v", fake.secrets["k"])
	}
	forbidden := errors.New("403 Forbidden")
	if err := (&SecretProviderAzure{client: &fakeAzure{err: forbidden}}).PutSecret(ctx, "k", "v"); !errors.Is(err, forbidden) {
		t.Fatalf("vault failure must surface, got %v", err)
	}
}

type fakeInfisical struct {
	infisical.SecretsInterface
	secrets   map[string]string
	updateErr error
}

func (f *fakeInfisical) Secrets() infisical.SecretsInterface { return f }

func (f *fakeInfisical) Update(o infisical.UpdateSecretOptions) (models.Secret, error) {
	if f.updateErr != nil {
		return models.Secret{}, f.updateErr
	}
	if _, ok := f.secrets[o.SecretKey]; !ok {
		return models.Secret{}, &infisicalerrors.APIError{StatusCode: 404}
	}
	f.secrets[o.SecretKey] = o.NewSecretValue
	return models.Secret{}, nil
}

func (f *fakeInfisical) Create(o infisical.CreateSecretOptions) (models.Secret, error) {
	if o.ProjectID == "" || o.Environment == "" || o.SecretPath != "/" {
		return models.Secret{}, errors.New("create is not scoped to the configured project/environment")
	}
	if f.secrets == nil {
		f.secrets = map[string]string{}
	}
	f.secrets[o.SecretKey] = o.SecretValue
	return models.Secret{}, nil
}

func TestInfisicalPutSecret(t *testing.T) {
	for label, fake := range map[string]*fakeInfisical{
		"existing": {secrets: map[string]string{"k": "old"}},
		"missing":  {},
	} {
		p := &SecretProviderInfisical{client: fake, projectID: "proj", environment: "prod"}
		if err := p.PutSecret(ctx, "k", "new"); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if fake.secrets["k"] != "new" {
			t.Fatalf("%s: stored %q, want new", label, fake.secrets["k"])
		}
	}

	denied := &fakeInfisical{updateErr: &infisicalerrors.APIError{StatusCode: 403}}
	p := &SecretProviderInfisical{client: denied, projectID: "proj", environment: "prod"}
	if err := p.PutSecret(ctx, "k", "v"); err == nil || len(denied.secrets) != 0 {
		t.Fatalf("a 403 must surface without falling through to create, got %v", err)
	}
}

var (
	_ gsmClient          = (*fakeGSM)(nil)
	_ awsSecretsClient   = (*fakeAWS)(nil)
	_ azureSecretsClient = (*fakeAzure)(nil)
	_ infisicalClient    = (*fakeInfisical)(nil)
)
