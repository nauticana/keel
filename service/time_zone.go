package service

import (
	"net/http"
	"strconv"

	"github.com/nauticana/keel/common"
)

// TimeZoneMiddleware binds the client's zone from common.TimeZoneHeader into
// the request context. A missing or unknown zone leaves UTC in place; the
// unknown one is logged so a broken client is visible.
func (h *HttpBackend) TimeZoneMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Header.Get(common.TimeZoneHeader)
		if name == "" {
			next.ServeHTTP(w, r)
			return
		}
		loc, err := common.ParseTimeZone(name)
		if err != nil {
			if h.Journal != nil {
				if len(name) > 64 {
					name = name[:64]
				}
				h.Journal.Warning("ignoring " + common.TimeZoneHeader + " " + strconv.Quote(name) + " on request " + common.RequestIDFromContext(r.Context()))
			}
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(common.WithLocation(r.Context(), loc)))
	})
}
