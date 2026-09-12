package model

// PrincipalKind selects which assignment table a principal's role grants come
// from. keel ships PrincipalUser; register others on a data.BaseGrantCatalog.
type PrincipalKind string

const PrincipalUser PrincipalKind = "user"

// Principal is the subject of an authorization decision. The zero value has no
// kind and is never authorized.
type Principal struct {
	Kind  PrincipalKind
	ID    any   // subject id, bound as a SQL argument: int for user_permission.user_id
	Scope []any // binds the kind's extra grant filters, in registration order
}

// UserPrincipal is the human subject identified by user_account.id.
func UserPrincipal(userID int) Principal {
	return Principal{Kind: PrincipalUser, ID: userID}
}

// Valid reports whether the principal names a subject; whether its kind is
// registered is settled where the grant query is resolved.
func (p Principal) Valid() bool {
	return p.Kind != "" && p.ID != nil
}

// TokenPrincipal is the identity carried by an OAuth 2.1 access token, produced
// by a port.TokenValidator. A token is one way to establish a subject, not one.
type TokenPrincipal struct {
	Subject  string
	Issuer   string
	Audience []string
	Scopes   []string
	Claims   map[string]any
}
