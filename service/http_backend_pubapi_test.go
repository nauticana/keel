package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/common"
)

func TestPubapiGateMetersUnlessUnmetered(t *testing.T) {
	svc, qs := newAPIKeys(t)
	qs.rows[validateAPIKey] = [][]any{{int64(5), int64(7), "query", time.Time{}, nil, nil}}
	for _, unmetered := range []bool{false, true} {
		quota := &scriptedQuota{allowed: false}
		h := (&HttpBackend{ApiKeyService: svc, QuotaService: quota, PubapiUnmetered: unmetered}).
			APIKeyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		r := httptest.NewRequest(http.MethodGet, common.PubapiPrefix+"/renew", nil)
		r.Header.Set("X-API-Key", "t_abc")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if metered := quota.calls == 1; metered == unmetered || (rec.Code == http.StatusOK) != unmetered {
			t.Errorf("unmetered=%v: status %d, quota calls %d", unmetered, rec.Code, quota.calls)
		}
	}
}
