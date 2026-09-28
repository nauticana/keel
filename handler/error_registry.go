package handler

import (
	"errors"
	"net/http"
	"sync"

	"github.com/nauticana/keel/model"
)

// Typed-error → HTTP status registry: services return sentinel errors, the handler
// boundary maps them to stable status via WriteServiceError instead of each handler
// hand-rolling an errors.Is ladder. Apps register their sentinels at wiring time.

var (
	errorStatusMu       sync.RWMutex
	errorStatusRegistry = map[error]errorRegistration{}
)

type errorRegistration struct {
	status  int
	code    string
	message string
}

// RegisterErrorStatus maps a sentinel error to the HTTP status WriteServiceError
// returns for it (and any error that wraps it, via errors.Is). Registering the
// same sentinel again overwrites the prior status. Call at init/wiring time.
func RegisterErrorStatus(sentinel error, status int) {
	RegisterErrorCode(sentinel, status, "")
}

// RegisterErrorCode maps a sentinel to an HTTP status and a stable
// machine-readable RFC 7807 code. Use it when clients must branch on the
// error reason without coupling to human-readable detail text.
func RegisterErrorCode(sentinel error, status int, code string) {
	RegisterErrorMessage(sentinel, status, code, "")
}

// RegisterErrorMessage is RegisterErrorCode with the public detail text, for a
// sentinel whose own text is not client wording; empty keeps the sentinel's.
func RegisterErrorMessage(sentinel error, status int, code, message string) {
	errorStatusMu.Lock()
	defer errorStatusMu.Unlock()
	errorStatusRegistry[sentinel] = errorRegistration{status: status, code: code, message: message}
}

// registrationForError returns the registered sentinel err matches (with
// errors.Is) and its registration, or nil when none matches.
func registrationForError(err error) (error, errorRegistration) {
	errorStatusMu.RLock()
	defer errorStatusMu.RUnlock()
	for sentinel, registration := range errorStatusRegistry {
		if errors.Is(err, sentinel) {
			return sentinel, registration
		}
	}
	return nil, errorRegistration{}
}

// WriteServiceError writes an RFC 7807 response whose status comes from the
// registry (errors.Is), else from a *model.AppError, defaulting to 500. The
// client never sees err.Error(): its detail is the registered message, else the
// registered sentinel's own text, else the AppError's Message, else the status
// text. The full cause is logged with the request_id — at warning for 4xx, at
// error for 5xx.
func (h *AbstractHandler) WriteServiceError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	sentinel, registration := registrationForError(err)
	status, code, detail := registration.status, registration.code, registration.message
	if detail == "" {
		detail = publicText(sentinel)
	}
	cause := err.Error()
	var appErr *model.AppError
	if errors.As(err, &appErr) {
		if status == 0 {
			status = appErr.Status
		}
		if code == "" {
			code = appErr.Code
		}
		if detail == "" {
			detail = appErr.Message
		}
		if appErr.Detail != "" {
			cause += " (" + appErr.Detail + ")"
		}
	}
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if detail == "" {
		detail = http.StatusText(status)
	}
	h.writeProblem(r, w, status, http.StatusText(status), detail, code, cause)
}

func publicText(sentinel error) string {
	var appErr *model.AppError
	if errors.As(sentinel, &appErr) {
		return appErr.Message
	}
	if sentinel == nil {
		return ""
	}
	return sentinel.Error()
}
