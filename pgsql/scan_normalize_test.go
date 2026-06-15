package pgsql

import (
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestNormalizeValue_NumericToFloat(t *testing.T) {
	// 3.50 → Int=350, Exp=-2 — the shape pgx hands back for
	// NUMERIC(18,2) values like trvoo's pricing_rate.base_fare.
	n := pgtype.Numeric{Int: big.NewInt(350), Exp: -2, Valid: true}
	got := normalizeValue(n)
	f, ok := got.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T (%v)", got, got)
	}
	if f != 3.50 {
		t.Errorf("expected 3.50, got %v", f)
	}
}

func TestNormalizeValue_NumericNullToNil(t *testing.T) {
	n := pgtype.Numeric{Valid: false}
	if got := normalizeValue(n); got != nil {
		t.Errorf("expected nil for NULL numeric, got %v", got)
	}
}

func TestNormalizeValue_NumericNaNPassesThroughAsFloat(t *testing.T) {
	// pgtype.Numeric{NaN:true} → Float8{Float64:NaN, Valid:true}, no
	// error. We surface math.NaN so callers using math.IsNaN can
	// detect "present but undefined". NULL still returns nil — those
	// are different domain states.
	n := pgtype.Numeric{NaN: true, Valid: true}
	got := normalizeValue(n)
	f, ok := got.(float64)
	if !ok {
		t.Fatalf("expected float64, got %T (%v)", got, got)
	}
	if !math.IsNaN(f) {
		t.Errorf("expected NaN, got %v", f)
	}
}

func TestNormalizeValue_DateToTime(t *testing.T) {
	when := time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC)
	d := pgtype.Date{Time: when, Valid: true}
	got := normalizeValue(d)
	tt, ok := got.(time.Time)
	if !ok {
		t.Fatalf("expected time.Time, got %T", got)
	}
	if !tt.Equal(when) {
		t.Errorf("expected %v, got %v", when, tt)
	}
}

func TestNormalizeValue_DateNullToNil(t *testing.T) {
	if got := normalizeValue(pgtype.Date{Valid: false}); got != nil {
		t.Errorf("expected nil for NULL date, got %v", got)
	}
}

func TestNormalizeValue_TimestampToTime(t *testing.T) {
	when := time.Date(2026, 5, 18, 22, 30, 0, 0, time.UTC)
	ts := pgtype.Timestamp{Time: when, Valid: true}
	got := normalizeValue(ts)
	if tt, ok := got.(time.Time); !ok || !tt.Equal(when) {
		t.Errorf("expected %v, got %T %v", when, got, got)
	}
}

func TestNormalizeValue_TimestamptzToTime(t *testing.T) {
	when := time.Date(2026, 5, 18, 22, 30, 0, 0, time.FixedZone("EST", -5*3600))
	tstz := pgtype.Timestamptz{Time: when, Valid: true}
	got := normalizeValue(tstz)
	if tt, ok := got.(time.Time); !ok || !tt.Equal(when) {
		t.Errorf("expected %v, got %T %v", when, got, got)
	}
}

func TestNormalizeValue_TimeToString(t *testing.T) {
	// 09:00:00 → 9*3600*1e6 microseconds since midnight (business_hours.opens).
	tm := pgtype.Time{Microseconds: int64(9*3600) * 1_000_000, Valid: true}
	got := normalizeValue(tm)
	s, ok := got.(string)
	if !ok {
		t.Fatalf("expected string, got %T (%v)", got, got)
	}
	if s != "09:00:00" {
		t.Errorf("expected 09:00:00, got %q", s)
	}
}

func TestNormalizeValue_TimeNullToNil(t *testing.T) {
	if got := normalizeValue(pgtype.Time{Valid: false}); got != nil {
		t.Errorf("expected nil for NULL time, got %v", got)
	}
}

func TestNormalizeValue_PassThrough(t *testing.T) {
	// Primitive types and unknown wrappers must round-trip untouched
	// so AsString / AsBool / AsInt* keep working as before.
	cases := []any{
		"hello",
		int64(42),
		3.14,
		true,
		nil,
		[]byte("blob"),
	}
	for _, c := range cases {
		got := normalizeValue(c)
		if got == nil && c != nil {
			t.Errorf("expected pass-through for %T, got nil", c)
		}
		// Type identity is enough; we don't deep-compare bytes here.
	}
}
