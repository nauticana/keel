package document

import (
	"context"
	"testing"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/dms"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type repoRows struct {
	port.QueryService
	rows [][]any
}

func (r repoRows) Query(_ context.Context, name string, _ ...any) (*model.QueryResult, error) {
	return &model.QueryResult{Rows: r.rows}, nil
}

type repoDB struct {
	port.DatabaseRepository
	qs port.QueryService
}

func (d repoDB) GetQueryService(context.Context, map[string]string) port.QueryService { return d.qs }

func TestTableCatalog(t *testing.T) {
	row := []any{"docs", "Documents", "s3", "acme-docs", nil, "eu-west-1", nil, nil, "https://cdn.example.com", "s3_docs", nil, "du", "read-only"}
	cat := &TableCatalog{DB: repoDB{qs: repoRows{rows: [][]any{row}}}}
	defs, err := cat.Repositories(context.Background())
	if err != nil || len(defs) != 1 {
		t.Fatalf("catalog: %v %v", defs, err)
	}
	d := defs[0]
	if d.ID != "docs" || d.Storage.Mode != "s3" || d.Storage.Bucket != "acme-docs" || d.Storage.Region != "eu-west-1" ||
		d.Storage.PublicBaseURL != "https://cdn.example.com" || d.Storage.CredentialSecret != "s3_docs" ||
		d.DefaultDocProt != "du" || d.Status != dms.StatusReadOnly || d.Prefix() != "docs/" {
		t.Errorf("definition: %+v", d)
	}
}

func TestTableCatalogFallsBackToFlags(t *testing.T) {
	c := config.Config()
	origEndpoint, origSecret := c.S3Endpoint, c.StorageCredentialSecret
	t.Cleanup(func() { c.S3Endpoint, c.StorageCredentialSecret = origEndpoint, origSecret })
	c.S3Endpoint, c.StorageCredentialSecret = "https://r2.example.com", "r2_key"
	row := []any{"docs", "Documents", "s3", "acme-prod", nil, nil, nil, nil, nil, nil, nil, nil, nil}
	defs, err := (&TableCatalog{DB: repoDB{qs: repoRows{rows: [][]any{row}}}}).Repositories(context.Background())
	if err != nil || defs[0].Storage.Mode != "s3" || defs[0].Storage.Bucket != "acme-prod" ||
		defs[0].Storage.Endpoint != "https://r2.example.com" || defs[0].Storage.CredentialSecret != "r2_key" || defs[0].Status != dms.StatusActive {
		t.Fatalf("fallback: %+v %v", defs, err)
	}
}
