package googleads

import (
	"errors"
	"fmt"
)

var (
	// ErrNoDeveloperToken means the caller supplied no developer token; no call is made.
	ErrNoDeveloperToken = errors.New("googleads: developer token is not configured")
	// ErrNoAccessToken means the call carried a blank OAuth access token.
	ErrNoAccessToken      = errors.New("googleads: access token is empty")
	ErrInvalidCustomerID  = errors.New("googleads: invalid customer id")
	ErrEmptyQuery         = errors.New("googleads: query is empty")
	ErrInvalidPhone       = errors.New("googleads: invalid phone number")
	ErrNoConversions      = errors.New("googleads: no conversions to upload")
	ErrTooManyConversions = fmt.Errorf("googleads: more than %d conversions in one upload", MaxConversionsPerUpload)
	// ErrConversionRejected is wrapped by every Failure of a partial-failure
	// upload; resending the same conversion will not help.
	ErrConversionRejected = errors.New("googleads: conversion rejected")
)
