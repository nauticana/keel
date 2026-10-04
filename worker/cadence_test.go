package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
)

func mustZone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	return loc
}

func TestCadenceNext(t *testing.T) {
	toronto := mustZone(t, "America/Toronto")
	at := func(s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02 15:04", s, toronto)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	monday9 := Weekly(time.Monday, 9*60, toronto)
	for _, tc := range []struct {
		name    string
		cadence Cadence
		after   time.Time
		want    time.Time
	}{
		{"later this week", monday9, at("2026-10-03 12:00"), at("2026-10-05 09:00")}, // Saturday
		{"same day before slot", monday9, at("2026-10-05 08:59"), at("2026-10-05 09:00")},
		{"exactly at slot is next week", monday9, at("2026-10-05 09:00"), at("2026-10-12 09:00")},
		{"across DST end", monday9, at("2026-10-30 10:00"), at("2026-11-02 09:00")},
		{"month day ahead", Monthly(15, 0, toronto), at("2026-10-03 00:00"), at("2026-10-15 00:00")},
		{"month day passed", Monthly(1, 0, toronto), at("2026-10-03 00:00"), at("2026-11-01 00:00")},
		{"31st clamps to February", Monthly(31, 60, toronto), at("2027-01-31 02:00"), at("2027-02-28 01:00")},
		{"31st clamps in leap year", Monthly(31, 60, toronto), at("2028-02-01 00:00"), at("2028-02-29 01:00")},
		{"December rolls the year", Monthly(5, 0, toronto), at("2026-12-06 00:00"), at("2027-01-05 00:00")},
	} {
		got := tc.cadence.next(tc.after)
		if !got.Equal(tc.want) || got.Location() != time.UTC {
			t.Errorf("%s: Next(%v) = %v, want %v in UTC", tc.name, tc.after, got, tc.want)
		}
	}
}

func TestScheduleCalendarValidates(t *testing.T) {
	s := newScheduler(&fakeQS{})
	for name, c := range map[string]Cadence{
		"interval kind": {Kind: CadenceInterval, Location: time.UTC},
		"no zone":       Weekly(time.Monday, 0, nil),
		"host zone":     Weekly(time.Monday, 0, time.Local),
		"fixed zone":    Weekly(time.Monday, 0, time.FixedZone("tenant-zone", 3*60*60)),
		"bad weekday":   {Kind: CadenceWeekly, Day: 7, Location: time.UTC},
		"day zero":      Monthly(0, 0, time.UTC),
		"day 32":        Monthly(32, 0, time.UTC),
		"minute 1440":   Monthly(1, 1440, time.UTC),
		"minute -1":     Weekly(time.Monday, -1, time.UTC),
	} {
		if err := s.ScheduleCalendar(context.Background(), 1, "report", c); !errors.Is(err, ErrInvalidCadence) {
			t.Errorf("%s: err = %v, want ErrInvalidCadence", name, err)
		}
	}
}

func TestScheduleCalendarUpserts(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	qs := &fakeQS{fixed: map[string]*model.QueryResult{qScheduleClock: qr([]any{now})}}
	c := Weekly(time.Monday, 9*60, mustZone(t, "Europe/Istanbul"))
	if err := newScheduler(qs).ScheduleCalendar(context.Background(), 7, "report", c); err != nil {
		t.Fatal(err)
	}
	args := qs.argsFor(qScheduleUpsert)
	if args[2].(int64) != 7*24*3600 || args[3] != "W" || args[4] != 1 || args[5] != 540 || args[6] != "Europe/Istanbul" {
		t.Fatalf("upsert args = %v", args)
	}
	if first := args[7].(time.Time); !first.After(now) || first.Sub(now) > 7*24*time.Hour || first.In(c.Location).Weekday() != time.Monday {
		t.Fatalf("first run %v is not the next slot", first)
	}
}

func TestCalendarTaskCompletesAtNextSlot(t *testing.T) {
	claimed := time.Date(2026, 10, 5, 6, 0, 30, 0, time.UTC) // Monday 09:00:30 in Istanbul
	completed := claimed.Add(8 * 24 * time.Hour)
	qs := &fakeQS{genID: 3, fixed: map[string]*model.QueryResult{
		qScheduleDue:   qr([]any{int64(7), int64(604800), int64(0), nil, int64(3), "W", int64(1), int64(540), "Europe/Istanbul"}),
		qScheduleDone:  qr([]any{int64(7)}),
		qScheduleClock: qr([]any{completed}),
	}}
	mustZone(t, "Europe/Istanbul")
	s := newScheduler(qs)
	tasks, err := s.Due(context.Background(), "report", 5)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("Due: %v %v", tasks, err)
	}
	if c := tasks[0].Cadence; c.Kind != CadenceWeekly || c.Day != 1 || c.Minute != 540 || c.Location.String() != "Europe/Istanbul" {
		t.Fatalf("cadence = %+v", c)
	}
	if err := s.Complete(context.Background(), tasks[0]); err != nil {
		t.Fatal(err)
	}
	if next := qs.argsFor(qScheduleDone)[0].(time.Time); !next.Equal(time.Date(2026, 10, 19, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("next run = %v, want the first Monday after completion", next)
	}
}

func TestCalendarTaskWithInvalidZoneRefusesComplete(t *testing.T) {
	qs := &fakeQS{fixed: map[string]*model.QueryResult{
		qScheduleDone:  qr([]any{int64(7)}),
		qScheduleClock: qr([]any{time.Now()}),
	}}
	s := newScheduler(qs)
	badZone := ScheduledTask{PartnerID: 7, TaskKind: "report", LeaseToken: 1, Cadence: Cadence{Kind: CadenceMonthly, Day: 1}}
	if err := s.Complete(context.Background(), badZone); !errors.Is(err, ErrInvalidCadence) {
		t.Errorf("unloadable zone: %v", err)
	}
	if qs.countCalls(qScheduleDone) != 0 {
		t.Error("a refused completion reached the database")
	}
}

func TestDueFailsUnusableCadenceInsteadOfRunningIt(t *testing.T) {
	mustZone(t, "Europe/Istanbul")
	qs := &fakeQS{genID: 3, fixed: map[string]*model.QueryResult{
		qScheduleDue: qr(
			[]any{int64(7), int64(604800), int64(0), nil, int64(3), "W", int64(1), int64(540), "Mars/Olympus"},
			[]any{int64(8), int64(604800), int64(0), nil, int64(3), "W", int64(1), int64(540), "Europe/Istanbul"},
		),
		qScheduleFail: qr([]any{int64(7)}),
	}}
	tasks, err := newScheduler(qs).Due(context.Background(), "report", 5)
	if err != nil || len(tasks) != 1 || tasks[0].PartnerID != 8 {
		t.Fatalf("Due = %+v, %v; want only partner 8", tasks, err)
	}
	if args := qs.argsFor(qScheduleFail); len(args) != 5 || args[2].(int64) != 7 || args[4].(int64) != 3 {
		t.Fatalf("unusable cadence not failed under its lease: %v", args)
	}
}
