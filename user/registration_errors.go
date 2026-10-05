package user

import (
	"errors"
)

var (
	// ErrInvalidConfirmation answers every bad, expired or unknown code alike,
	// so a probe cannot tell whether an email registered.
	ErrInvalidConfirmation = errors.New("invalid or expired confirmation")
	ErrAlreadyMember       = errors.New("user: the account already belongs to a partner")
	// ErrAccountExists: an identity signup matched an existing account, which
	// signs in and adds its partner with CreatePartner.
	ErrAccountExists = errors.New("user: an account already exists for this identity")
	ErrPublicEmail   = errors.New("user: a business email address is required")
	// ErrCheckout: the partner was created but its checkout session was not.
	// The other returned values are valid; PaymentURL is empty.
	ErrCheckout = errors.New("user: checkout session failed")
	// ErrConsentNotRecorded: the signup committed but its consent was not
	// recorded. The other returned values are valid.
	ErrConsentNotRecorded = errors.New("user: signup consent not recorded")
)
