package data

import (
	"context"

	"github.com/nauticana/keel/model"
)

type TableService interface {
	Init() error
	GetTable() *model.TableDefinition
	Get(ctx context.Context, partnerID int64, userID int, where map[string]any, orderby string) ([]any, error)
	Insert(ctx context.Context, partnerID int64, userID int, data any) ([]int64, error)
	Update(ctx context.Context, userID int, data any) error
	Post(ctx context.Context, partnerID int64, userID int, data ...any) error
	Delete(ctx context.Context, partnerID int64, userID int, where map[string]any) error
	CheckPermission(ctx context.Context, userID int, task string) bool
}
