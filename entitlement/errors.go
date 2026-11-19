// Package entitlement is the signed entitlement a vendor's portal issues and an installation verifies offline: one
// document naming the customer, the installation, the plan, its quotas, when it expires, and how long its grace
// lasts, signed with RSA-PSS over SHA-256. Nothing here names a product's quotas; the product defines their keys.
package entitlement

import "errors"

var (
	// ErrMalformed refuses a file or document that is not in the canonical form.
	ErrMalformed = errors.New("entitlement: malformed")
	// ErrUnsupported refuses a signature algorithm or document format this version does not read.
	ErrUnsupported = errors.New("entitlement: unsupported algorithm or format")
	// ErrUnknownKey refuses a file signed by a key the verifier does not hold.
	ErrUnknownKey = errors.New("entitlement: unknown signing key")
	// ErrSignature refuses a file whose signature does not match its document.
	ErrSignature = errors.New("entitlement: signature does not match")
	// ErrInvalid refuses a document whose fields are incomplete or inconsistent.
	ErrInvalid = errors.New("entitlement: invalid document")
	// ErrWeakKey refuses an RSA key shorter than MinKeyBits.
	ErrWeakKey = errors.New("entitlement: RSA key too short")
)
