package common

import (
	"math"
	"testing"
	"time"
)

func TestBackoffDelay(t *testing.T) {
	full := func() float64 { return 1 }
	b := Backoff{Base: 2 * time.Second, Max: time.Hour, Entropy: full}
	for attempt, want := range map[int]time.Duration{-3: 2 * time.Second, 1: 2 * time.Second, 3: 8 * time.Second, 11: 2048 * time.Second, 12: time.Hour, 1 << 30: time.Hour} {
		if got := b.Delay(attempt); got != want {
			t.Fatalf("Delay(%d) = %v, want %v", attempt, got, want)
		}
	}
	b.Entropy = func() float64 { return 0 }
	if got := b.Delay(3); got != 4*time.Second {
		t.Fatalf("no jitter draw = %v, want half the delay", got)
	}
}

func TestBackoffHonorsMaxBelowBaseAndBadEntropy(t *testing.T) {
	b := Backoff{Base: time.Minute, Max: time.Second, Entropy: func() float64 { return 1 }}
	if got := b.Delay(5); got != time.Second {
		t.Fatalf("Max below Base: %v, want Max", got)
	}
	b.Entropy = math.NaN
	if got := b.Delay(5); got != time.Second/2 {
		t.Fatalf("NaN entropy: %v, want half the delay", got)
	}
}

func TestBackoffZeroValueIsSafe(t *testing.T) {
	var b Backoff
	if got := b.Delay(1); got < 500*time.Millisecond || got > time.Second {
		t.Fatalf("zero value Delay(1) = %v, want within one second", got)
	}
	b.Entropy = func() float64 { return 1 }
	if got := b.Delay(1 << 30); got <= 0 {
		t.Fatalf("uncapped Delay overflowed to %v", got)
	}
}
