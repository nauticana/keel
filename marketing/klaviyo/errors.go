package klaviyo

import "errors"

var (
	// ErrInvalidArgument is a request refused before any call, such as a blank API key.
	ErrInvalidArgument = errors.New("klaviyo: invalid argument")
	// ErrMalformedResponse is a 2xx response that is not the documented JSON:API body.
	ErrMalformedResponse = errors.New("klaviyo: malformed response")
	// ErrNotFound is a lookup, such as a metric by name, that matched nothing.
	ErrNotFound = errors.New("klaviyo: not found")
	// ErrTooManyPages is a listing that did not end within outbound_max_pages.
	ErrTooManyPages = errors.New("klaviyo: listing exceeds the page limit")
	// ErrTooManyItems is a listing that exceeds outbound_max_items.
	ErrTooManyItems = errors.New("klaviyo: listing exceeds the item limit")
)
