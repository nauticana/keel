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
	status int
	code   string
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
	errorStatusMu.Lock()
	defer errorStatusMu.Unlock()
	errorStatusRegistry[sentinel] = errorRegistration{status: status, code: code}
}

// registrationForError returns the registration for err (matched with
// errors.Is), or the zero value when no registered sentinel matches.
func registrationForError(err error) errorRegistration {
	errorStatusMu.RLock()
	defer errorStatusMu.RUnlock()
	for sentinel, registration := range errorStatusRegistry {
		if errors.Is(err, sentinel) {
			return registration
		}
	}
	return errorRegistration{}
}

// WriteServiceError writes an RFC 7807 response whose status comes from the
// registry (errors.Is), defaulting to 500. Like WriteError, 5xx is sanitized +
// logged; 4xx passes the error text through.
func (h *AbstractHandler) WriteServiceError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	// A typed *model.AppError carries its own status (e.g. a FORBIDDEN
	// authorization failure); honor it before the sentinel registry.
	registration := registrationForError(err)
	status := registration.status
	var appErr *model.AppError
	if status == 0 && errors.As(err, &appErr) {
		status = appErr.Status
	}
	if status == 0 {
		status = http.StatusInternalServerError
	}
	h.writeProblem(r, w, status, http.StatusText(status), err.Error(), registration.code)
}
