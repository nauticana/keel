package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

type scriptedQuota struct {
	allowed bool
	resetAt time.Time
	err     error
	calls   int
}

func (s *scriptedQuota) ConsumeQuota(context.Context, int64, string, int64, string) (bool, time.Time, error) {
	s.calls++
	return s.allowed, s.resetAt, s.err
}
func (s *scriptedQuota) CheckQuota(context.Context, int64, string, int64) (bool, error) {
	return s.allowed, s.err
}
func (*scriptedQuota) CheckAddon(context.Context, int64, string) (bool, error) { return true, nil }
func (*scriptedQuota) GetPartnerQuota(context.Context, int64, string, int64) (int64, error) {
	return 0, nil
}
func (*scriptedQuota) LogUsage(context.Context, int64, string, int64, string) error { return nil }
func (*scriptedQuota) ReportAddonUsage(context.Context, int64, string, int64, string) error {
	return nil
}

var _ port.QuotaService = (*scriptedQuota)(nil)

func quotaRequest(partnerID int64) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	if partnerID > 0 {
		r = r.WithContext(context.WithValue(r.Context(), common.PartnerID, partnerID))
	}
	return r
}

func runQuotaMW(q port.QuotaService, r *http.Request) *httptest.ResponseRecorder {
	h := QuotaMiddleware(q, "", "", nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestQuotaMiddlewareAllows(t *testing.T) {
	q := &scriptedQuota{allowed: true}
	rec := runQuotaMW(q, quotaRequest(7))
	if rec.Code != http.StatusOK || q.calls != 1 {
		t.Fatalf("code=%d calls=%d", rec.Code, q.calls)
	}
}

func TestQuotaMiddlewareDeniesWithRetryAfter(t *testing.T) {
	q := &scriptedQuota{allowed: false, resetAt: time.Now().UTC().Add(90 * time.Second)}
	rec := runQuotaMW(q, quotaRequest(7))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("code=%d, want 429", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type=%q", ct)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("Retry-After=%q", ra)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "API quota exceeded" {
		t.Fatalf("body=%s err=%v", rec.Body.String(), err)
	}
}

func TestQuotaMiddlewareDeniesAllTimeWithoutRetryAfter(t *testing.T) {
	rec := runQuotaMW(&scriptedQuota{allowed: false}, quotaRequest(7))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("code=%d Retry-After=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestQuotaMiddlewareFailsClosedOnError(t *testing.T) {
	rec := runQuotaMW(&scriptedQuota{err: errors.New("db down")}, quotaRequest(7))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, want 500", rec.Code)
	}
}

func TestQuotaMiddlewareAnonymousPassThrough(t *testing.T) {
	q := &scriptedQuota{allowed: false}
	rec := runQuotaMW(q, quotaRequest(0))
	if rec.Code != http.StatusOK || q.calls != 0 {
		t.Fatalf("code=%d calls=%d, want 200 with no quota call", rec.Code, q.calls)
	}
}
