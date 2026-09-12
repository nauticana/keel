package port

import (
	"context"

	"github.com/nauticana/keel/model"
)

type TableService interface {
	Init() error
	GetTable() *model.TableDefinition
	Get(ctx context.Context, partnerID int64, userID int, where map[string]any, orderby string) ([]any, error)
	Insert(ctx context.Context, partnerID int64, userID int, data any) ([]int64, error)
	Update(ctx context.Context, partnerID int64, userID int, data any) error
	// Patch writes only the columns named in changes (column or Pascal names);
	// key selects the row. Update is full-row: an unlisted column becomes NULL.
	Patch(ctx context.Context, partnerID int64, userID int, key map[string]any, changes map[string]any) error
	Post(ctx context.Context, partnerID int64, userID int, data ...any) error
	Delete(ctx context.Context, partnerID int64, userID int, where map[string]any) error
	CheckPermission(ctx context.Context, principal model.Principal, task string) (allowed bool, ownScope bool)
}

// PagedTableService is an optional TableService capability that pushes LIMIT /
// OFFSET into the query and reports the unpaged row count, so a bounded
// response no longer costs a full-table read. Implementations must impose a
// total order — rows tied under the caller's ordering would otherwise repeat
// or vanish between pages. A TableService that does not implement it still
// works: callers fall back to reading the collection and slicing.
type PagedTableService interface {
	GetPage(ctx context.Context, partnerID int64, userID int, where map[string]any, page model.PageRequest) (items []any, total int, err error)
}
