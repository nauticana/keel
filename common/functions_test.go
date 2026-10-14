package common

import (
	"strconv"
	"testing"
	"time"
)

func TestAsStringTimeIsRFC3339(t *testing.T) {
	loc := time.FixedZone("CET", 3600)
	got := AsString(time.Date(2026, 11, 12, 1, 0, 0, 0, loc))
	if got != "2026-11-12T00:00:00Z" {
		t.Fatalf("want RFC 3339 UTC, got %q", got)
	}
	if _, ok := AsTimeOK(got); !ok {
		t.Fatalf("AsString output must round-trip through AsTimeOK")
	}
}

func TestNullIfEmpty(t *testing.T) {
	if NullIfEmpty("  ") != nil || NullIfEmpty("") != nil {
		t.Error("blank should be nil")
	}
	if NullIfEmpty("x") != "x" {
		t.Error("non-blank should pass through")
	}
}

func TestSlugify(t *testing.T) {
	for in, want := range map[string]string{
		"  Rinova Pergola ": "rinova-pergola",
		"Café 99":           "caf-99",
		"UPPER_case":        "upper-case",
		"a  &  b":           "a-b",
	} {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q)=%q want %q", in, got, want)
		}
	}
}

func TestGenerateNumericCode(t *testing.T) {
	c, err := GenerateNumericCode(6)
	if err != nil || len(c) != 6 {
		t.Fatalf("code=%q err=%v", c, err)
	}
	if _, err := strconv.Atoi(c); err != nil {
		t.Errorf("not numeric: %q", c)
	}
	if _, err := GenerateNumericCode(0); err == nil {
		t.Error("digits=0 should error")
	}
	if _, err := GenerateNumericCode(19); err == nil {
		t.Error("digits=19 should error")
	}
}

func TestAsBool(t *testing.T) {
	for _, v := range []any{true, "true", "1", []byte("1"), int64(1), int32(1), 1} {
		if !AsBool(v) {
			t.Errorf("AsBool(%#v) = false", v)
		}
	}
	for _, v := range []any{nil, false, "false", "0", int64(0), 0, 1.0} {
		if AsBool(v) {
			t.Errorf("AsBool(%#v) = true", v)
		}
	}
}
