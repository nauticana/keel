package meta

import (
	"errors"
	"fmt"
)

var (
	ErrNoAccessToken = errors.New("meta: access token is empty")
	ErrInvalidID     = errors.New("meta: invalid graph id")
	// ErrPageLimit means a paged read exceeded outbound_max_pages or outbound_max_items; nothing is returned.
	ErrPageLimit = errors.New("meta: paging limit reached")
	// ErrForeignPagingURL means a next link pointed off the Graph host.
	ErrForeignPagingURL = errors.New("meta: paging link leaves the graph host")
	ErrInvalidQuery     = errors.New("meta: invalid insights query")
	ErrInvalidPhone     = errors.New("meta: invalid phone number")
	ErrNoEvents         = errors.New("meta: no events to send")
	ErrTooManyEvents    = fmt.Errorf("meta: more than %d events in one request", MaxEventsPerRequest)
	ErrInvalidEvent     = errors.New("meta: invalid server event")
	// ErrEventsNotReceived means Meta acknowledged fewer events than were sent.
	ErrEventsNotReceived = errors.New("meta: not every event was received")
)
