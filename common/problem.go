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
	// Details is a machine-readable extension member, such as the items a
	// client must change; never set on a 5xx.
	Details any `json:"details,omitempty"`
}

// InternalErrorDetail replaces every 5xx detail so internal context never reaches a client.
const InternalErrorDetail = "internal server error — see request_id in your logs"

// WriteProblem writes p as application/problem+json with p.Status. status is
// a JSON number as RFC 9457 requires; details is API JSON (see EncodeJSON).
func WriteProblem(w http.ResponseWriter, p ProblemDetail) error {
	var details json.RawMessage
	if p.Details != nil {
		var err error
		if details, err = MarshalJSON(p.Details); err != nil {
			return err
		}
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	type wire ProblemDetail
	return json.NewEncoder(w).Encode(struct {
		wire
		Details json.RawMessage `json:"details,omitempty"`
	}{wire(p), details})
}
