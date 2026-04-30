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
