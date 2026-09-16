package common

import "time"

// Period is a half-open effective-dated interval: From inclusive, To exclusive, and a zero To open-ended.
type Period struct {
	From time.Time
	To   time.Time
}

func (p Period) Contains(t time.Time) bool {
	return !t.Before(p.From) && (p.To.IsZero() || t.Before(p.To))
}

// Ordered reports whether the interval is well-formed; an empty interval is not.
func (p Period) Ordered() bool { return p.To.IsZero() || p.From.Before(p.To) }
