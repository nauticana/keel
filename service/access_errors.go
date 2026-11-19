package service

import "errors"

var (
	// ErrForbidden is a caller without the grant the operation requires.
	ErrForbidden = errors.New("the caller is not authorized for this operation")
	// ErrNotFound is a record that does not exist or belongs to another tenant.
	ErrNotFound = errors.New("not found")
	// ErrTxCatalog is a caller's transaction that cannot bind a service query catalog.
	ErrTxCatalog = errors.New("the transaction cannot bind the service query catalog")
)
