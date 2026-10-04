package service

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/nauticana/keel/port"
)

const (
	qHealthPing   = "health_ping"
	healthTimeout = 2 * time.Second
)

// Health serves an unauthenticated health check: 200 "ok" when db answers a
// ping within two seconds, 503 otherwise.
func Health(db port.DatabaseRepository) http.HandlerFunc {
	var (
		once sync.Once
		qs   port.QueryService
	)
	return func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		once.Do(func() { qs = db.GetQueryService(context.Background(), map[string]string{qHealthPing: "SELECT 1"}) })
		ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
		defer cancel()
		if qs == nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if _, err := qs.Query(ctx, qHealthPing); err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}
