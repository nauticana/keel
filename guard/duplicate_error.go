package guard

import "errors"

// ErrDuplicateInFlight: an equivalent request is already in flight or was
// satisfied inside the debounce window. Callers should return the existing id
// (via *DuplicateError) instead of writing again.
var ErrDuplicateInFlight = errors.New("trust guard: duplicate request in flight")

// ErrGuardRejected: a guard refused on policy (too new, over rate/velocity).
var ErrGuardRejected = errors.New("trust guard: request rejected")

// DuplicateError carries the id a duplicate guard matched. Unwraps to ErrDuplicateInFlight.
type DuplicateError struct {
	ExistingID int64
}

func (e *DuplicateError) Error() string {
	return ErrDuplicateInFlight.Error()
}

func (e *DuplicateError) Unwrap() error {
	return ErrDuplicateInFlight
}
