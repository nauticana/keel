package common

import (
	"strconv"
	"testing"
)

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
