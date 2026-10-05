// Package domain records how a partner proved a domain. It keeps every
// method's evidence with history, re-check, lapse and cancellation; each
// consumer decides which methods it honors.
package domain

import "errors"

var (
	ErrDomainNotFound = errors.New("domain verification: the partner has no such domain")
	ErrInvalidDomain  = errors.New("domain verification: the domain cannot be verified")
	ErrUnknownMethod  = errors.New("domain verification: method is unknown or not configured for this operation")
	ErrNotMember      = errors.New("domain verification: the user is not a current member of the partner")
	ErrDomainHeld     = errors.New("domain verification: another partner holds identity evidence for the domain")
	ErrNoChallenge    = errors.New("domain verification: no open challenge")
	ErrTooManyTries   = errors.New("domain verification: too many confirmation attempts")
	ErrCooldown       = errors.New("domain verification: a challenge was issued too recently")
	ErrRecipient      = errors.New("domain verification: the recipient address is not on the domain")
	ErrNoVerification = errors.New("domain verification: no current verification")
	ErrNotHeld        = errors.New("domain verification: no single partner holds identity evidence for the domain")
)
