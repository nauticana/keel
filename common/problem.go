package common

import (
	"encoding/json"
	"net/http"
)

// ProblemDetail is the RFC 7807 error envelope keel answers with.
type ProblemDetail struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Code      string `json:"code,omitempty"`
	Instance  string `json:"instance,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// InternalErrorDetail replaces every 5xx detail so internal context never reaches a client.
const InternalErrorDetail = "internal server error — see request_id in your logs"

// WriteProblem writes p as application/problem+json with p.Status.
func WriteProblem(w http.ResponseWriter, p ProblemDetail) error {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	return json.NewEncoder(w).Encode(p)
}
