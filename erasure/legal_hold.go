package erasure

import "time"

// LegalHold is an unreleased hold on a user's data.
type LegalHold struct {
	ID       int64     `json:"id"`
	UserID   int       `json:"user_id"`
	Reason   string    `json:"reason"`
	PlacedBy int       `json:"placed_by"`
	PlacedAt time.Time `json:"placed_at"`
}
