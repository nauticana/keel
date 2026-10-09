package common

import (
	"strings"
	"testing"
)

func TestNewRequestIDIsValidAndDistinct(t *testing.T) {
	a, b := NewRequestID(), NewRequestID()
	if len(a) != 12 || !ValidRequestID(a) || a == b {
		t.Fatalf("ids %q %q", a, b)
	}
}

func TestValidRequestID(t *testing.T) {
	for id, want := range map[string]bool{
		"":                       false,
		"req-1.a:b_C":            true,
		strings.Repeat("a", 128): true,
		strings.Repeat("a", 129): false,
		"with space":             false,
		"crlf\r\n":               false,
		"quote\"":                false,
		"ünicode":                false,
	} {
		if got := ValidRequestID(id); got != want {
			t.Errorf("ValidRequestID(%q) = %v, want %v", id, got, want)
		}
	}
}
