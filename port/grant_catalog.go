package port

import "github.com/nauticana/keel/model"

// GrantCatalog resolves how each principal kind's role grants are queried, so
// authorization works the same for every kind. Inject one into the data layer
// and RestService; data.BaseGrantCatalog is the shipped implementation.
type GrantCatalog interface {
	// Queries returns the SQL to register with a QueryService.
	Queries() map[string]string
	// CheckQuery names the single-grant lookup for a kind.
	CheckQuery(kind model.PrincipalKind) string
	// ReadQuery names the full-grant-list lookup for a kind.
	ReadQuery(kind model.PrincipalKind) string
	// Args returns a principal's bind arguments, erroring when its kind is
	// unregistered or its scope arity is wrong, so a check fails closed.
	Args(p model.Principal) ([]any, error)
}

// GrantCatalogProvider exposes the catalog already configured on a repository.
type GrantCatalogProvider interface {
	Grants() GrantCatalog
}
