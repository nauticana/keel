package meta

import (
	"encoding/json"
	"fmt"

	"github.com/nauticana/keel/common"
)

// APIError is a non-2xx Graph response decoded from its error envelope. It
// unwraps to the *common.HTTPStatusError, whose Transient and Unauthorized
// classify it by HTTP status.
type APIError struct {
	HTTPStatus int
	Code       int
	Subcode    int
	Type       string
	Message    string
	TraceID    string
	cause      *common.HTTPStatusError
}

func newAPIError(se *common.HTTPStatusError) *APIError {
	e := &APIError{HTTPStatus: se.Status, cause: se}
	var env struct {
		Error *struct {
			Message   string `json:"message"`
			Type      string `json:"type"`
			Code      int    `json:"code"`
			Subcode   int    `json:"error_subcode"`
			FBTraceID string `json:"fbtrace_id"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(se.Body), &env) == nil && env.Error != nil {
		e.Code, e.Subcode, e.Type, e.Message, e.TraceID = env.Error.Code, env.Error.Subcode, env.Error.Type, env.Error.Message, env.Error.FBTraceID
	}
	return e
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("http %d", e.HTTPStatus)
	if e.Type != "" {
		msg += " " + e.Type
	}
	if e.Code != 0 {
		msg += fmt.Sprintf(" (#%d", e.Code)
		if e.Subcode != 0 {
			msg += fmt.Sprintf("/%d", e.Subcode)
		}
		msg += ")"
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

func (e *APIError) Unwrap() error { return e.cause }

// TokenInvalid reports Graph code 190: the token expired, was revoked or the
// user changed their password; the grant must be renewed.
func (e *APIError) TokenInvalid() bool { return e.Code == 190 }

// Throttled reports Graph's application, user, Page and ads rate-limit codes.
func (e *APIError) Throttled() bool {
	switch e.Code {
	case 4, 17, 32, 613:
		return true
	}
	return e.Code >= 80000 && e.Code <= 80014
}
