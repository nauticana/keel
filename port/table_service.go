package port

import (
	"context"
	"strings"

	"github.com/nauticana/keel/model"
)

type TableService interface {
	Init() error
	GetTable() *model.TableDefinition
	Get(ctx context.Context, partnerID int64, userID int, where map[string]any, orderby string) ([]any, error)
	Insert(ctx context.Context, partnerID int64, userID int, data any) ([]int64, error)
	Update(ctx context.Context, partnerID int64, userID int, data any) error
	Post(ctx context.Context, partnerID int64, userID int, data ...any) error
	Delete(ctx context.Context, partnerID int64, userID int, where map[string]any) error
	CheckPermission(ctx context.Context, userID int, task string) (allowed bool, ownScope bool)
}

// PageRequest bounds a collection read. Limit <= 0 means unbounded.
type PageRequest struct {
	Limit   int
	Offset  int
	OrderBy string
}

// StableOrderBy returns OrderBy with every key column it does not already name
// appended, so the ordering is total. Paged reads need that: rows tied under the
// caller's ordering otherwise come back in whatever order the plan produces, and
// a client walking offsets can see one row twice and miss another. An empty
// OrderBy yields the key columns alone.
//
// This is the string-level form of the rule, for callers handing an ordering to
// a TableService.Get they cannot inspect. Implementations that parse the order
// themselves (see pgsql.TableServicePgsql.stableOrder) apply the same rule to
// validated terms instead. Terms are comma-separated, matching the grammar
// documented for ?order=.
func (p PageRequest) StableOrderBy(keys []string) string {
	named := make(map[string]bool, len(keys))
	for _, term := range strings.Split(p.OrderBy, ",") {
		if fields := strings.Fields(term); len(fields) > 0 {
			named[strings.ToLower(fields[0])] = true
		}
	}
	var terms []string
	if trimmed := strings.TrimSpace(p.OrderBy); trimmed != "" {
		terms = append(terms, trimmed)
	}
	for _, key := range keys {
		if !named[strings.ToLower(key)] {
			terms = append(terms, key)
		}
	}
	return strings.Join(terms, ", ")
}

// Slice applies the bounds in memory, for fallback paths that could not push
// them into the query.
func (p PageRequest) Slice(items []any) []any {
	start := p.Offset
	if start < 0 {
		start = 0
	}
	if start >= len(items) {
		return []any{}
	}
	end := len(items)
	if p.Limit > 0 && start+p.Limit < end {
		end = start + p.Limit
	}
	return items[start:end]
}

// PagedTableService is an optional TableService capability that pushes LIMIT /
// OFFSET into the query and reports the unpaged row count, so a bounded
// response no longer costs a full-table read. Implementations must impose a
// total order — rows tied under the caller's ordering would otherwise repeat
// or vanish between pages. A TableService that does not implement it still
// works: callers fall back to reading the collection and slicing.
type PagedTableService interface {
	GetPage(ctx context.Context, partnerID int64, userID int, where map[string]any, page PageRequest) (items []any, total int, err error)
}
