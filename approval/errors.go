// Package approval is maker-checker approval of an application record: one
// user submits, a second user decides, and both are audited.
package approval

import "errors"

var (
	ErrNotFound     = errors.New("approval: request not found")
	ErrInvalidState = errors.New("approval: request is already decided")
	ErrAlreadyOpen  = errors.New("approval: the record already has an open request")
	ErrSameActor    = errors.New("approval: the maker cannot decide their own request")
	ErrExpired      = errors.New("approval: request has expired")
	ErrNotMaker     = errors.New("approval: only the maker can withdraw the request")
	ErrTxCatalog    = errors.New("approval: transaction cannot bind the approval query catalog")

	ErrNotAdministrator   = errors.New("approval: only an administrator of the owner can change its policy")
	ErrPolicyConfirmation = errors.New("approval: a policy change is confirmed by another administrator")
	ErrNoPendingPolicy    = errors.New("approval: no policy change awaits confirmation")
)

const (
	StatusPending   = "P"
	StatusApproved  = "A"
	StatusRejected  = "R"
	StatusWithdrawn = "W"
	StatusExpired   = "E"

	EventSubmitted = "S"
	EventApproved  = "A"
	EventRejected  = "R"
	EventWithdrawn = "W"
	EventExpired   = "E"
)
