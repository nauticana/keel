// Package actiontoken mints single-use tokens that authorize exactly one action,
// never a session, for links that cross an untrusted channel such as email or chat.
package actiontoken

import (
	"errors"
	"fmt"
)

var (
	ErrInvalid        = errors.New("actiontoken: token is invalid, expired, revoked, or bound to another action")
	ErrInFlight       = errors.New("actiontoken: the action is already running")
	ErrUnknownOutcome = errors.New("actiontoken: action outcome is unknown")
	ErrResultTooLarge = errors.New("actiontoken: result exceeds 64 KiB")

	errDatabase = errors.New("actiontoken: database is required")
	errLedger   = errors.New("actiontoken: reconciliation ledger is required")
	errNoRun    = errors.New("actiontoken: a run function is required")
)

// Failure is a run outcome that provably did not perform the action, such as a
// failed authorization check. It is recorded and returned on every replay.
type Failure struct {
	Reason string
}

func (f *Failure) Error() string { return "actiontoken: action failed: " + f.Reason }

// UnknownOutcome identifies the claim that must be reconciled.
type UnknownOutcome struct {
	ClaimID int64
	cause   error
}

func (e *UnknownOutcome) Error() string {
	return fmt.Sprintf("actiontoken: claim %d outcome is unknown", e.ClaimID)
}

func (e *UnknownOutcome) Is(target error) bool { return target == ErrUnknownOutcome }

func (e *UnknownOutcome) Unwrap() error { return e.cause }

func unknown(claimID int64, errs ...error) error {
	return &UnknownOutcome{ClaimID: claimID, cause: errors.Join(errs...)}
}
