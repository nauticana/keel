package sheets

import "testing"

func TestColumnLetter(t *testing.T) {
	for i, want := range map[int]string{-1: "", 0: "A", 25: "Z", 26: "AA", 51: "AZ", 52: "BA", 701: "ZZ", 702: "AAA"} {
		if got := ColumnLetter(i); got != want {
			t.Errorf("ColumnLetter(%d) = %q, want %q", i, got, want)
		}
	}
}

func TestQuoteSheetDoublesApostrophes(t *testing.T) {
	if got := QuoteSheet("Bob's Leads"); got != "'Bob''s Leads'" {
		t.Fatalf("got %s", got)
	}
}

func TestCellA1(t *testing.T) {
	if got := CellA1("Leads", 2, 7); got != "'Leads'!C7" {
		t.Fatalf("got %s", got)
	}
}
