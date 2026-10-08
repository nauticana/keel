package oidc

import (
	"errors"
	"fmt"
)

var (
	// ErrBadConfiguration: the connection or the issuer's metadata is unusable.
	ErrBadConfiguration = errors.New("oidc: identity provider configuration is invalid")
	// ErrInvalidResponse: the callback, token response or ID token failed a check.
	ErrInvalidResponse = errors.New("oidc: identity provider response is invalid")
	// ErrProviderDisabled: a first-party provider has no client id configured.
	ErrProviderDisabled = errors.New("sign-in provider is not enabled")
	// ErrEmailNotVerified: the provider does not vouch for the account's email.
	ErrEmailNotVerified = errors.New("oidc: email not verified")
)

// TokenError is an OAuth error answer from a token endpoint, or an answer
// without the expected token. Its fields come from the provider.
type TokenError struct {
	Code        string
	Description string
}

func (e *TokenError) Error() string {
	if e.Code == "" {
		return "token exchange failed"
	}
	msg := "token exchange failed: " + e.Code
	if e.Description != "" {
		msg += " — " + e.Description
	}
	return msg
}

// CallbackError is an error the IdP returned to the redirect URI instead of a code.
type CallbackError struct {
	Code string
}

func (e *CallbackError) Error() string {
	return fmt.Sprintf("oidc: identity provider returned %q", e.Code)
}

func (e *CallbackError) Unwrap() error { return ErrInvalidResponse }
