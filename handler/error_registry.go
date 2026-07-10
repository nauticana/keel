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
	errorStatusRegistry = map[error]int{}
)

// RegisterErrorStatus maps a sentinel error to the HTTP status WriteServiceError
// returns for it (and any error that wraps it, via errors.Is). Registering the
// same sentinel again overwrites the prior status. Call at init/wiring time.
func RegisterErrorStatus(sentinel error, status int) {
	errorStatusMu.Lock()
	defer errorStatusMu.Unlock()
	errorStatusRegistry[sentinel] = status
}

// statusForError returns the registered status for err (matched with errors.Is),
// or 0 when no registered sentinel matches.
func statusForError(err error) int {
	errorStatusMu.RLock()
	defer errorStatusMu.RUnlock()
	for sentinel, status := range errorStatusRegistry {
		if errors.Is(err, sentinel) {
			return status
		}
	}
	return 0
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
	status := statusForError(err)
	var appErr *model.AppError
	if status == 0 && errors.As(err, &appErr) {
		status = appErr.Status
	}
	if status == 0 {
		status = http.StatusInternalServerError
	}
	h.writeError(r, w, status, http.StatusText(status), err.Error())
}
