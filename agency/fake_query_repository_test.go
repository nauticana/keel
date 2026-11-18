package agency

import (
	"context"

	"github.com/nauticana/keel/port"
)

// fakeQueryRepository serves one query service and nothing else.
type fakeQueryRepository struct {
	port.DatabaseRepository
	qs port.QueryService
}

func (r fakeQueryRepository) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r.qs
}
