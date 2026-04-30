package common

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
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

func writeEnvelope(w http.ResponseWriter, status int, data interface{}, pagination interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := APIResponse{
		Data:       data,
		Pagination: pagination,
		Meta: &APIMeta{
			RequestID: newRequestID(),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Version:   "v1",
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "req_" + time.Now().UTC().Format("20060102T150405.000000")
	}
	return "req_" + hex.EncodeToString(b)
}
