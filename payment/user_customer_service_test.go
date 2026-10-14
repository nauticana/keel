package payment

import (
	"context"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type customerQS struct {
	port.QueryService
	rows [][]any
	args []any
}

func (q *customerQS) Query(_ context.Context, _ string, args ...any) (*model.QueryResult, error) {
	q.args = args
	return &model.QueryResult{Rows: q.rows}, nil
}

type customerRepo struct {
	port.DatabaseRepository
	qs port.QueryService
}

func (r customerRepo) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r.qs
}

func TestUserCustomerService_UsesSessionUser(t *testing.T) {
	qs := &customerQS{rows: [][]any{{"cus_1"}}}
	s := &UserCustomerService{DB: customerRepo{qs: qs}, Provider: ProviderStripe}
	id, err := s.CustomerID(context.Background(), &model.UserSession{Id: 7, PartnerId: 2})
	if err != nil || id != "cus_1" || qs.args[0] != 7 || qs.args[1] != ProviderStripe {
		t.Fatalf("id=%q err=%v args=%v", id, err, qs.args)
	}
	if err := s.LinkCustomer(context.Background(), &model.UserSession{Id: 7}, "cus_2"); err != nil || qs.args[0] != 7 || qs.args[2] != "cus_2" {
		t.Fatalf("link err=%v args=%v", err, qs.args)
	}
	if _, err := s.CustomerID(context.Background(), nil); err == nil {
		t.Fatal("resolved a customer without a session")
	}
	if err := s.LinkCustomer(context.Background(), &model.UserSession{}, "cus_2"); err == nil {
		t.Fatal("linked a customer to a zero user")
	}
}
