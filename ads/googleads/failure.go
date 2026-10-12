package googleads

import "fmt"

// Failure is one GoogleAdsError. Index is the position of the offending
// operation or conversion in the request, or -1 when the error names none.
// Category is the errorCode oneof name (such as "conversionUploadError") and
// Code its enum value (such as "UNPARSEABLE_GCLID").
type Failure struct {
	Index    int
	Category string
	Code     string
	Message  string
}

func (f Failure) Error() string {
	return fmt.Sprintf("googleads: conversion %d rejected: %s.%s: %s", f.Index, f.Category, f.Code, f.Message)
}

func (f Failure) Unwrap() error { return ErrConversionRejected }
