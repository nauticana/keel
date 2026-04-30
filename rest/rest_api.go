package rest

import (
	"context"

	"github.com/nauticana/keel/model"
)

type RestAPI struct {
	APIName   string
	Version   string
	Relations RelationAPI
}

func (s *RestAPI) Init() error {
	return s.Relations.Init()
}

func (s *RestAPI) GetTable() *model.TableDefinition {
	return s.Relations.GetTable()
}

func (s *RestAPI) Get(ctx context.Context, partnerID int64, userID int, where map[string]any, order string) ([]any, error) {
	return s.Relations.Get(ctx, partnerID, userID, where, order)
}

func (s *RestAPI) List(ctx context.Context, partnerID int64, userID int, where map[string]any, order string) ([]any, error) {
	return s.Relations.List(ctx, partnerID, userID, where, order)
}

func (s *RestAPI) Insert(ctx context.Context, partnerID int64, userID int, data any) ([]int64, error) {
	return s.Relations.Insert(ctx, partnerID, userID, data)
}

func (s *RestAPI) Update(ctx context.Context, userID int, data any) error {
	return s.Relations.Update(ctx, userID, data)
}

func (s *RestAPI) Delete(ctx context.Context, partnerID int64, userID int, where map[string]any) error {
	return s.Relations.Delete(ctx, partnerID, userID, where)
}

func (s *RestAPI) Post(ctx context.Context, partnerID int64, userID int, data ...any) error {
	return s.Relations.Post(ctx, partnerID, userID, data...)
}

func (s *RestAPI) GetDefinition() map[string]any {
	return s.Relations.GetDefinition(s.APIName, s.Version)
}
