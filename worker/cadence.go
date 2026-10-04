package worker

import (
	"errors"
	"fmt"
	"time"
)

// CadenceKind is a work_schedule_cadence code.
type CadenceKind string

const (
	CadenceInterval CadenceKind = "I"
	CadenceWeekly   CadenceKind = "W"
	CadenceMonthly  CadenceKind = "M"
)

var ErrInvalidCadence = errors.New("scheduler: invalid cadence")

const minutesPerDay = 24 * 60

// Cadence is a calendar-aligned schedule: a weekday (Weekly) or a day of the
// month (Monthly, clamped to the month's last day), at Minute past local
// midnight in Location. The zero value is the interval cadence.
type Cadence struct {
	Kind     CadenceKind
	Day      int // time.Weekday for Weekly, 1..31 for Monthly
	Minute   int // 0..1439
	Location *time.Location
}

func Weekly(day time.Weekday, minute int, loc *time.Location) Cadence {
	return Cadence{Kind: CadenceWeekly, Day: int(day), Minute: minute, Location: loc}
}

func Monthly(day, minute int, loc *time.Location) Cadence {
	return Cadence{Kind: CadenceMonthly, Day: day, Minute: minute, Location: loc}
}

func (c Cadence) calendar() bool { return c.Kind == CadenceWeekly || c.Kind == CadenceMonthly }

func (c Cadence) normalized() (Cadence, error) {
	if c.Minute < 0 || c.Minute >= minutesPerDay {
		return Cadence{}, fmt.Errorf("%w: minute %d is outside 0..1439", ErrInvalidCadence, c.Minute)
	}
	// time.Local names the host's zone, which another replica may not share.
	if c.Location == nil || c.Location == time.Local {
		return Cadence{}, fmt.Errorf("%w: a named time zone is required", ErrInvalidCadence)
	}
	switch c.Kind {
	case CadenceWeekly:
		if c.Day < int(time.Sunday) || c.Day > int(time.Saturday) {
			return Cadence{}, fmt.Errorf("%w: weekday %d", ErrInvalidCadence, c.Day)
		}
	case CadenceMonthly:
		if c.Day < 1 || c.Day > 31 {
			return Cadence{}, fmt.Errorf("%w: day of month %d", ErrInvalidCadence, c.Day)
		}
	default:
		return Cadence{}, fmt.Errorf("%w: kind %q", ErrInvalidCadence, c.Kind)
	}
	loc, err := time.LoadLocation(c.Location.String())
	if err != nil {
		return Cadence{}, fmt.Errorf("%w: unknown time zone %q", ErrInvalidCadence, c.Location.String())
	}
	c.Location = loc
	return c, nil
}

// period is the nominal gap between runs; it bases the failure backoff.
func (c Cadence) period() time.Duration {
	if c.Kind == CadenceWeekly {
		return 7 * 24 * time.Hour
	}
	return 28 * 24 * time.Hour
}

// next returns the first slot strictly after t, in UTC.
func (c Cadence) next(t time.Time) time.Time {
	local := t.In(c.Location)
	slot := func(year int, month time.Month, day int) time.Time {
		return time.Date(year, month, day, c.Minute/60, c.Minute%60, 0, 0, c.Location)
	}
	var next time.Time
	if c.Kind == CadenceWeekly {
		ahead := (c.Day - int(local.Weekday()) + 7) % 7
		next = slot(local.Year(), local.Month(), local.Day()+ahead)
		if !next.After(t) {
			next = slot(local.Year(), local.Month(), local.Day()+ahead+7)
		}
	} else {
		next = c.monthSlot(local.Year(), local.Month(), slot)
		if !next.After(t) {
			next = c.monthSlot(local.Year(), local.Month()+1, slot)
		}
	}
	return next.UTC()
}

func (c Cadence) monthSlot(year int, month time.Month, slot func(int, time.Month, int) time.Time) time.Time {
	last := time.Date(year, month+1, 0, 0, 0, 0, 0, c.Location).Day()
	first := time.Date(year, month, 1, 0, 0, 0, 0, c.Location)
	return slot(first.Year(), first.Month(), min(c.Day, last))
}
