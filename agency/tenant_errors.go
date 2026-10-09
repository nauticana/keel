package agency

import (
	"errors"

	"github.com/nauticana/keel/model"
)

var (
	// ErrTenantNotFound also answers a tenant the caller may not act in, so a
	// foreign partner id is never confirmed to exist.
	ErrTenantNotFound = errors.New("agency: tenant not found")
	ErrTenantRequired = errors.New("agency: tenant is required: the caller can act in several")
	ErrTenantCaller   = errors.New("agency: caller is not an active user or API key")
)

// TenantChoiceError is ErrTenantRequired carrying the tenants to choose from.
type TenantChoiceError struct {
	Choices []model.Tenant
}

func (e *TenantChoiceError) Error() string        { return ErrTenantRequired.Error() }
func (e *TenantChoiceError) Is(target error) bool { return target == ErrTenantRequired }
