package common

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/nauticana/keel/config"
)

// APIResponse is the standard envelope returned by every keel-served REST
// endpoint. `pagination` is omitempty so detail (non-list) responses stay
// compact — list endpoints fill it via WriteJSONPaged.
type APIResponse struct {
	Data       any      `json:"data,omitempty"`
	Pagination any      `json:"pagination,omitempty"`
	Meta       *APIMeta `json:"meta"`
}

type APIMeta struct {
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
}

// WriteJSON emits `{data, meta}` for non-paginated responses.
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	writeEnvelope(w, status, data, nil)
}

// WriteJSONPaged emits `{data, pagination, meta}` for list responses.
// `pagination` is typically a struct with limit/offset/total/has_more/
// next_offset fields, but any JSON-marshallable value is accepted.
func WriteJSONPaged(w http.ResponseWriter, status int, data interface{}, pagination interface{}) {
	writeEnvelope(w, status, data, pagination)
}

// WriteJSONError emits the flat `{"error": msg}` body used by middleware
// error paths (not the {data, meta} envelope).
func WriteJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeEnvelope(w http.ResponseWriter, status int, data interface{}, pagination interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := APIResponse{
		Data:       data,
		Pagination: pagination,
		Meta: &APIMeta{
			RequestID: responseRequestID(w),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Version:   "v1",
		},
	}
	json.NewEncoder(w).Encode(resp)
}

// responseRequestID reuses the middleware-bound id, then its response header.
func responseRequestID(w http.ResponseWriter) string {
	for current, depth := w, 0; current != nil && depth < 16; depth++ {
		if carrier, ok := current.(interface{ RequestID() string }); ok {
			if id := carrier.RequestID(); id != "" {
				return id
			}
		}
		unwrapper, ok := current.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		current = unwrapper.Unwrap()
	}
	if header := config.Config().RequestIDHeader; header != "" {
		if id := w.Header().Get(header); id != "" {
			return id
		}
	}
	return NewRequestID()
}
