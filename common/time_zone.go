package common

import (
	"context"
	"errors"
	"time"
)

// TimeZoneHeader carries the client's IANA zone name on each request. It is
// display state for server-rendered output and is never persisted.
const TimeZoneHeader = "X-Time-Zone"

const maxTimeZoneLen = 64

var ErrInvalidTimeZone = errors.New("invalid time zone")

// ParseTimeZone accepts an IANA zone name such as Europe/Istanbul or UTC.
func ParseTimeZone(name string) (*time.Location, error) {
	if name == "" || len(name) > maxTimeZoneLen {
		return nil, ErrInvalidTimeZone
	}
	loc, err := time.LoadLocation(name)
	if err != nil || name == "Local" {
		return nil, ErrInvalidTimeZone
	}
	return loc, nil
}

func WithLocation(ctx context.Context, loc *time.Location) context.Context {
	if loc == nil {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, TimeZone, loc)
}

// LocationFromContext returns the caller's zone, or UTC when none was bound:
// background work and logging render in UTC.
func LocationFromContext(ctx context.Context) *time.Location {
	if ctx != nil {
		if loc, ok := ctx.Value(TimeZone).(*time.Location); ok && loc != nil {
			return loc
		}
	}
	return time.UTC
}

// FormatTime renders t for a human in loc (UTC when nil). The zero time is
// an unset value and renders empty. Transport uses AsString, not this.
func FormatTime(t time.Time, loc *time.Location, layout string) string {
	if t.IsZero() {
		return ""
	}
	if loc == nil {
		loc = time.UTC
	}
	return t.In(loc).Format(layout)
}
