// Package approval is maker-checker approval of an application record: one
// user submits, a second user decides, and both are audited.
package approval

import "errors"

var (
	ErrNotFound     = errors.New("approval: request not found")
	ErrInvalidState = errors.New("approval: request is already decided")
	ErrAlreadyOpen  = errors.New("approval: the record already has an open request")
	ErrSameActor    = errors.New("approval: the maker cannot decide their own request")
)

const (
	StatusPending  = "P"
	StatusApproved = "A"
	StatusRejected = "R"

	EventSubmitted = "S"
	EventApproved  = "A"
	EventRejected  = "R"
)
