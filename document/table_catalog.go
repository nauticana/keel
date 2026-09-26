package document

import (
	"context"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/dms"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/storage"
)

// TableCatalog serves dms repository definitions from the content_repository
// table. The location (storage_mode, bucket) is always the row's; the access
// path columns fall back to the matching flags when empty.
type TableCatalog struct {
	DB port.DatabaseRepository

	once sync.Once
	qs   port.QueryService
}

var _ dms.RepositoryCatalog = (*TableCatalog)(nil)

func (c *TableCatalog) Repositories(ctx context.Context) ([]dms.RepositoryDefinition, error) {
	c.once.Do(func() { c.qs = c.DB.GetQueryService(ctx, queries) })
	res, err := c.qs.Query(ctx, qListRepositories)
	if err != nil {
		return nil, err
	}
	flags := config.Config()
	defs := make([]dms.RepositoryDefinition, 0, len(res.Rows))
	for _, r := range res.Rows {
		defs = append(defs, dms.RepositoryDefinition{
			ID:      common.AsString(r[0]),
			Caption: common.AsString(r[1]),
			Storage: storage.Spec{
				Mode: common.AsString(r[2]), Bucket: common.AsString(r[3]), Project: common.AsString(r[4]),
				Region: common.AsString(r[5]), Endpoint: orFlag(r[6], flags.S3Endpoint), AccountURL: orFlag(r[7], flags.StorageAccountURL),
				PublicBaseURL: orFlag(r[8], flags.StoragePublicBaseURL), CredentialSecret: orFlag(r[9], flags.StorageCredentialSecret),
			},
			PathPrefix:     common.AsString(r[10]),
			DefaultDocProt: common.AsString(r[11]),
			Status:         dms.RepositoryStatus(orFlag(r[12], string(dms.StatusActive))),
		})
	}
	return defs, nil
}

func orFlag(v any, flag string) string {
	if s := common.AsString(v); s != "" {
		return s
	}
	return flag
}
