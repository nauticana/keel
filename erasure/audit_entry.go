package erasure

import "time"

// AuditEntry records what an erasure request did to one row.
type AuditEntry struct {
	Table      string    `json:"table"`
	Key        string    `json:"key"`
	Action     Action    `json:"action"`
	Reason     string    `json:"reason,omitempty"`
	ExecutedAt time.Time `json:"executed_at"`
}
