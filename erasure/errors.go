package erasure

import "errors"

var (
	ErrNotFound          = errors.New("erasure: request not found")
	ErrUserNotFound      = errors.New("erasure: user not found")
	ErrNotCancellable    = errors.New("erasure: request already started or finished")
	ErrNotExecutable     = errors.New("erasure: request cannot be executed in its current state")
	ErrRequestUser       = errors.New("erasure: request belongs to a different user")
	ErrReasonRequired    = errors.New("erasure: a reason is required")
	ErrHoldNotFound      = errors.New("erasure: no unreleased legal hold with that id")
	ErrUnknownPseudonym  = errors.New("erasure: unknown pseudonym")
	ErrInvalidItem       = errors.New("erasure: classifier returned an invalid item")
	ErrInvalidClassifier = errors.New("erasure: invalid classifier set")
	ErrTxCatalog         = errors.New("erasure: transaction cannot bind a classifier query catalog")
)
