package erasure

import "time"

const (
	StatusPending   = "P"
	StatusActive    = "A"
	StatusHeld      = "H"
	StatusDone      = "D"
	StatusFailed    = "F"
	StatusCancelled = "X"
)

// Request is one user's erasure request.
type Request struct {
	ID          int64     `json:"id"`
	UserID      int       `json:"user_id"`
	Status      string    `json:"status"`
	RequestedBy int       `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
	Attempts    int       `json:"attempts"`
	CompletedAt time.Time `json:"completed_at,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
}
