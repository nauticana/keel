package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/nauticana/keel/config"
)

// APIResponse is the standard envelope returned by every keel-served REST
// endpoint, written with EncodeJSON. `pagination` is omitempty so detail
// (non-list) responses stay compact — list endpoints fill it via WriteJSONPaged.
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

// ErrEmptyData reports an envelope whose data member is missing or null.
var ErrEmptyData = errors.New("api response: no data")

// DecodeAPIResponse reads one `{data, meta}` envelope of at most maxBytes from
// r, decoding data with the API JSON rules. The caller checks the status first;
// an error body is not an envelope.
func DecodeAPIResponse[T any](r io.Reader, maxBytes int64) (T, *APIMeta, error) {
	var data T
	if maxBytes < 1 || maxBytes == math.MaxInt64 {
		return data, nil, fmt.Errorf("api response: invalid body limit %d", maxBytes)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
		Meta *APIMeta        `json:"meta"`
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return data, nil, err
	}
	if int64(len(body)) > maxBytes {
		return data, nil, fmt.Errorf("api response: body exceeds %d bytes", maxBytes)
	}
	if err := DecodeJSON(body, &env); err != nil {
		return data, nil, fmt.Errorf("api response: %w", err)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return data, env.Meta, ErrEmptyData
	}
	if err := DecodeJSON(env.Data, &data); err != nil {
		return data, env.Meta, fmt.Errorf("api response data: %w", err)
	}
	return data, env.Meta, nil
}

// WriteJSON emits `{data, meta}` for non-paginated responses.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	writeEnvelope(w, status, data, nil)
}

// WriteJSONPaged emits `{data, pagination, meta}` for list responses.
// `pagination` is typically a struct with limit/offset/total/has_more/
// next_offset fields, but any JSON-marshallable value is accepted.
func WriteJSONPaged(w http.ResponseWriter, status int, data any, pagination any) {
	writeEnvelope(w, status, data, pagination)
}

// WriteJSONError emits the flat `{"error": msg}` body used by middleware
// error paths (not the {data, meta} envelope).
func WriteJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	EncodeJSON(w, map[string]string{"error": msg})
}

func writeEnvelope(w http.ResponseWriter, status int, data any, pagination any) {
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
	EncodeJSON(w, resp)
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
