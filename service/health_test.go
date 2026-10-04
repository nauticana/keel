package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// blockingQS blocks every query until its context ends.
type blockingQS struct{}

func (blockingQS) Query(ctx context.Context, _ string, _ ...any) (*model.QueryResult, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (blockingQS) GenID() int64 { return 1 }

type healthRepo struct {
	port.DatabaseRepository
	qs port.QueryService
}

func (r healthRepo) GetQueryService(context.Context, map[string]string) port.QueryService {
	return r.qs
}

func healthStatus(t *testing.T, h http.HandlerFunc, ctx context.Context) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/health", nil).WithContext(ctx))
	return rec.Code, rec.Body.String()
}

func TestHealth(t *testing.T) {
	if code, body := healthStatus(t, Health(nil), context.Background()); code != http.StatusServiceUnavailable || body != "unavailable\n" {
		t.Fatalf("nil db: %d %q", code, body)
	}

	qs := newQuotaFakeQS()
	if code, _ := healthStatus(t, Health(healthRepo{qs: qs}), context.Background()); code != http.StatusOK || qs.callIndex(qHealthPing) != 0 {
		t.Fatalf("healthy db: %d, calls %v", code, qs.calls)
	}

	qs.errs[qHealthPing] = errors.New("pq: password authentication failed for user app")
	code, body := healthStatus(t, Health(healthRepo{qs: qs}), context.Background())
	if code != http.StatusServiceUnavailable || body != "unavailable\n" {
		t.Fatalf("failing db must be 503 without detail: %d %q", code, body)
	}

	if code, _ := healthStatus(t, Health(healthRepo{}), context.Background()); code != http.StatusServiceUnavailable {
		t.Fatalf("no query service: %d", code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code, _ := healthStatus(t, Health(healthRepo{qs: blockingQS{}}), ctx); code != http.StatusServiceUnavailable {
		t.Fatalf("stalled db: %d", code)
	}
}
