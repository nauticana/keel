package model

import "fmt"

const (
	ErrNotFound     = "NOT_FOUND"
	ErrForbidden    = "FORBIDDEN"
	ErrBadRequest   = "BAD_REQUEST"
	ErrUnauthorized = "UNAUTHORIZED"
	ErrInternal     = "INTERNAL"
	ErrConflict     = "CONFLICT"
)

type AppError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

func (e *AppError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func NewAppError(code string, status int, message string) *AppError {
	return &AppError{Code: code, Status: status, Message: message}
}

// NewForbidden is an authorization failure (403) — a caller lacking a required
// permission, not a server fault. Handlers surface its message and status
// directly instead of a sanitised 500.
func NewForbidden(message string) *AppError {
	return &AppError{Code: ErrForbidden, Status: 403, Message: message}
}

// NewBadRequest is malformed caller input (400) — an unresolvable column name,
// an unparseable value. The server is healthy, so the message reaches the
// client instead of being sanitised into a 500 the caller cannot act on.
func NewBadRequest(message string) *AppError {
	return &AppError{Code: ErrBadRequest, Status: 400, Message: message}
}
