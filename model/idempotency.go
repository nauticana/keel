package model

// LedgerState is where an idempotency key stands; the zero value means it was never begun.
type LedgerState string

const (
	LedgerNew       LedgerState = ""
	LedgerInFlight  LedgerState = "in-flight"
	LedgerCompleted LedgerState = "completed"
	// LedgerUnknown is an operation whose outcome could not be established; it blocks retries until reconciled.
	LedgerUnknown LedgerState = "unknown"
)

// LedgerEntry is the recorded state of one key and, once completed, its non-nil opaque result. Fence is set only
// when Begin granted the claim to the caller; every later write must present it.
type LedgerEntry struct {
	State  LedgerState
	Result []byte
	Fence  string
}
