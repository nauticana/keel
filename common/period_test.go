package common

import (
	"testing"
	"time"
)

func TestPeriod(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	open := Period{From: from}
	closed := Period{From: from, To: from.AddDate(0, 0, 10)}
	if !open.Contains(from) || open.Contains(from.Add(-1)) || !open.Contains(from.AddDate(10, 0, 0)) {
		t.Fatal("open period bounds")
	}
	if !closed.Contains(from.AddDate(0, 0, 9)) || closed.Contains(from.AddDate(0, 0, 10)) {
		t.Fatal("closed period: To is exclusive")
	}
	if !open.Ordered() || !closed.Ordered() || (Period{From: from, To: from}).Ordered() {
		t.Fatal("ordering")
	}
}
