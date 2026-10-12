package sheets

import "errors"

var (
	// ErrInvalidArgument is a blank token, spreadsheet ID, range or cell reference.
	ErrInvalidArgument = errors.New("sheets: invalid argument")
	// ErrMalformedResponse is a 2xx response whose body is not the documented JSON.
	ErrMalformedResponse = errors.New("sheets: malformed response")
)
