package googleads

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/nauticana/keel/common"
)

// APIError is a non-2xx response decoded from Google's error envelope. It
// unwraps to the *common.HTTPStatusError, whose Transient and Unauthorized
// classify it.
type APIError struct {
	HTTPStatus int
	Status     string // google.rpc code name, such as "INVALID_ARGUMENT"
	Message    string
	RequestID  string
	Failures   []Failure
	cause      *common.HTTPStatusError
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("http %d", e.HTTPStatus)
	if e.Status != "" {
		msg += " " + e.Status
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if len(e.Failures) > 0 {
		msg += " (" + e.Failures[0].Category + "." + e.Failures[0].Code + ")"
	}
	return msg
}

func (e *APIError) Unwrap() error { return e.cause }

type rpcStatus struct {
	Code    int                `json:"code"`
	Message string             `json:"message"`
	Status  string             `json:"status"`
	Details []googleAdsFailure `json:"details"`
}

type googleAdsFailure struct {
	Errors []struct {
		ErrorCode map[string]any `json:"errorCode"`
		Message   string         `json:"message"`
		Location  struct {
			FieldPathElements []struct {
				FieldName string `json:"fieldName"`
				Index     *int   `json:"index"`
			} `json:"fieldPathElements"`
		} `json:"location"`
	} `json:"errors"`
	RequestID string `json:"requestId"`
}

func (s rpcStatus) failures() ([]Failure, string) {
	var out []Failure
	var requestID string
	for _, d := range s.Details {
		if d.RequestID != "" {
			requestID = d.RequestID
		}
		for _, e := range d.Errors {
			f := Failure{Index: -1, Message: e.Message}
			keys := make([]string, 0, len(e.ErrorCode))
			for k := range e.ErrorCode {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(keys) > 0 {
				f.Category, f.Code = keys[0], fmt.Sprint(e.ErrorCode[keys[0]])
			}
			for _, p := range e.Location.FieldPathElements {
				if p.Index != nil {
					f.Index = *p.Index
					break
				}
			}
			out = append(out, f)
		}
	}
	return out, requestID
}

// wrapError maps a RequestJSON failure: a status error becomes an *APIError,
// anything else is wrapped as is. No header or token enters the message.
func wrapError(op string, err error) error {
	var se *common.HTTPStatusError
	if !errors.As(err, &se) {
		return fmt.Errorf("googleads: %s: %w", op, err)
	}
	apiErr := &APIError{HTTPStatus: se.Status, cause: se}
	if st, ok := decodeStatus(se.Body); ok {
		apiErr.Status, apiErr.Message = st.Status, st.Message
		apiErr.Failures, apiErr.RequestID = st.failures()
	}
	if se.Header != nil && apiErr.RequestID == "" {
		apiErr.RequestID = se.Header.Get("request-id")
	}
	if errors.Is(err, common.ErrResponseTooLarge) {
		return fmt.Errorf("googleads: %s: %w", op, errors.Join(apiErr, common.ErrResponseTooLarge))
	}
	return fmt.Errorf("googleads: %s: %w", op, apiErr)
}

// decodeStatus reads {"error":{...}}, or the one-element array searchStream
// wraps it in.
func decodeStatus(body string) (rpcStatus, bool) {
	type envelope struct {
		Error *rpcStatus `json:"error"`
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "[") {
		var arr []envelope
		if json.Unmarshal([]byte(trimmed), &arr) == nil && len(arr) > 0 && arr[0].Error != nil {
			return *arr[0].Error, true
		}
		return rpcStatus{}, false
	}
	var env envelope
	if json.Unmarshal([]byte(trimmed), &env) == nil && env.Error != nil {
		return *env.Error, true
	}
	return rpcStatus{}, false
}
