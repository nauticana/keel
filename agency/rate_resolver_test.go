package agency

import (
	"context"
	"testing"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type rateResolverTx struct{}

func (f *rateResolverTx) Query(_ context.Context, name string, _ ...any) (*model.QueryResult, error) {
	switch name {
	case qRateGet:
		return &model.QueryResult{}, nil
	case qRateInsert:
		// Simulates a valid agency_profile override even though the program
		// default is unavailable. SQL validates the resolved value.
		return &model.QueryResult{Rows: [][]any{{int64(2750)}}}, nil
	default:
		return &model.QueryResult{}, nil
	}
}

func (f *rateResolverTx) QueryService(string, map[string]string) port.QueryService { return f }
func (f *rateResolverTx) GenID() int64                                             { return 1 }
func (f *rateResolverTx) Commit(context.Context) error                             { return nil }
func (f *rateResolverTx) Rollback(context.Context) error                           { return nil }

func TestFrozenRateAllowsAgencyOverrideWhenProgramDefaultUnavailable(t *testing.T) {
	previous := config.Config().DefaultCommissionRateBP
	config.Config().DefaultCommissionRateBP = 0
	t.Cleanup(func() { config.Config().DefaultCommissionRateBP = previous })

	rate, err := NewBaseFrozenRateResolver().Resolve(context.Background(), &rateResolverTx{}, 10, 20)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rate != 2750 {
		t.Fatalf("rate = %d, want agency override 2750", rate)
	}
}

var _ port.TxQueryService = (*rateResolverTx)(nil)
var _ port.TxQueryCatalog = (*rateResolverTx)(nil)
