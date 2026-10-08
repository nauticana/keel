package sso

import "errors"

var (
	// ErrUnavailable: no tenant holds the address's domain with an active
	// connection. It never says which part was missing.
	ErrUnavailable = errors.New("sso: single sign-on is not available for this address")
	// ErrSignInFailed: the callback, the identity provider's answer or the
	// pending sign-in was invalid or expired.
	ErrSignInFailed = errors.New("sso: sign-in failed")
	// ErrMFARequired: the connection requires multi-factor authentication and
	// the identity provider did not report it.
	ErrMFARequired = errors.New("sso: multi-factor authentication is required")
	// ErrEmailNotAllowed: the asserted email or hosted domain is outside the
	// domains the partner holds by identity-grade evidence.
	ErrEmailNotAllowed = errors.New("sso: the identity is outside the organization's verified domains")
	// ErrNoAccount: no account exists and the partner does not create
	// accounts on first sign-in.
	ErrNoAccount = errors.New("sso: no account for this identity")
	// ErrOtherPartner: the account belongs to another partner.
	ErrOtherPartner = errors.New("sso: the account belongs to another organization")
	// ErrTestMismatch: a test sign-in asserted someone other than the tester.
	ErrTestMismatch = errors.New("sso: the test sign-in asserted a different person")

	// ErrConnectionNotFound: no connection with that id belongs to the partner.
	ErrConnectionNotFound = errors.New("sso: identity provider connection not found")
	// ErrInvalidConfiguration: a connection setting is malformed or not allowed.
	ErrInvalidConfiguration = errors.New("sso: invalid identity provider configuration")
	// ErrConnectionActive: an active connection's issuer or client cannot change.
	ErrConnectionActive = errors.New("sso: disable the connection before changing its issuer or client")
	// ErrNotTested: the connection has no successful test sign-in.
	ErrNotTested = errors.New("sso: the connection has not passed a test sign-in")
	// ErrNoIdentityDomain: the partner holds no domain by identity-grade evidence.
	ErrNoIdentityDomain = errors.New("sso: the organization holds no verified domain")
)
