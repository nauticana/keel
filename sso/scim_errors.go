package sso

import "errors"

// SCIM errors carry the RFC 7644 status and scimType through SCIMError.
var (
	// ErrSCIMUnauthorized: the bearer token is missing, unknown, revoked or expired.
	ErrSCIMUnauthorized = errors.New("scim: invalid provisioning token")
	// ErrSCIMNotFound: no such user or group in the token's partner.
	ErrSCIMNotFound = errors.New("scim: resource not found")
	// ErrSCIMConflict: another resource already has the userName, externalId,
	// displayName or email, or the account belongs to another partner.
	ErrSCIMConflict = errors.New("scim: resource already exists")
	// ErrSCIMInvalidValue: a required attribute is missing or malformed, or an
	// email lies outside the partner's verified domains.
	ErrSCIMInvalidValue = errors.New("scim: invalid attribute value")
	// ErrSCIMInvalidFilter: a filter uses an attribute, operator or syntax keel
	// does not support.
	ErrSCIMInvalidFilter = errors.New("scim: unsupported filter")
	// ErrSCIMInvalidPath: a PATCH path the resource schema does not define or
	// keel does not support.
	ErrSCIMInvalidPath = errors.New("scim: unsupported patch path")
	// ErrSCIMNoTarget: a PATCH remove names no path.
	ErrSCIMNoTarget = errors.New("scim: patch operation has no target")
	// ErrSCIMMutability: a PATCH changes an immutable attribute.
	ErrSCIMMutability = errors.New("scim: attribute cannot be modified")
	// ErrSCIMTooMany: a request exceeds an operation, member or token limit.
	ErrSCIMTooMany = errors.New("scim: request exceeds a limit")
)
