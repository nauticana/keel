package common

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseTimeZone(t *testing.T) {
	loc, err := ParseTimeZone("Europe/Istanbul")
	if err != nil || loc.String() != "Europe/Istanbul" {
		t.Fatalf("got %v, %v", loc, err)
	}
	for _, bad := range []string{"", "Local", "Mars/Olympus", "../../etc/passwd", strings.Repeat("a", 65)} {
		if _, err := ParseTimeZone(bad); !errors.Is(err, ErrInvalidTimeZone) {
			t.Errorf("%q: want ErrInvalidTimeZone, got %v", bad, err)
		}
	}
}

func TestLocationFromContextDefaultsToUTC(t *testing.T) {
	if LocationFromContext(nil) != time.UTC || LocationFromContext(context.Background()) != time.UTC {
		t.Fatal("missing zone must read as UTC")
	}
	loc, _ := ParseTimeZone("Asia/Tokyo")
	if got := LocationFromContext(WithLocation(context.Background(), loc)); got != loc {
		t.Fatalf("got %v", got)
	}
	if WithLocation(context.Background(), nil).Value(TimeZone) != nil {
		t.Fatal("nil location must not be bound")
	}
}

func TestFormatTime(t *testing.T) {
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	loc, _ := ParseTimeZone("Europe/Istanbul")
	if got := FormatTime(at, loc, "2006-01-02 15:04"); got != "2026-11-12 03:00" {
		t.Fatalf("session zone: %q", got)
	}
	if got := FormatTime(at, nil, time.RFC3339); got != "2026-11-12T00:00:00Z" {
		t.Fatalf("nil zone must be UTC: %q", got)
	}
	if FormatTime(time.Time{}, loc, time.RFC3339) != "" {
		t.Fatal("zero time must render empty")
	}
}
