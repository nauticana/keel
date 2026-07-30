package agency

import "testing"

func TestCumulativeReversalShareCarriesRoundingForward(t *testing.T) {
	first, err := cumulativeReversalShare(1, 0, 0, 1, 2)
	if err != nil {
		t.Fatalf("first share: %v", err)
	}
	if first != 0 {
		t.Fatalf("first share = %d, want 0 from half-even rounding", first)
	}
	second, err := cumulativeReversalShare(1, first, 1, 1, 2)
	if err != nil {
		t.Fatalf("second share: %v", err)
	}
	if second != 1 {
		t.Fatalf("second share = %d, want the carried cent", second)
	}
}

func TestCumulativeReversalShareReachesExactOriginal(t *testing.T) {
	already := int64(0)
	for before := int64(0); before < 3; before++ {
		share, err := cumulativeReversalShare(10, already, before, 1, 3)
		if err != nil {
			t.Fatalf("share %d: %v", before, err)
		}
		already += share
	}
	if already != 10 {
		t.Fatalf("total reversed = %d, want 10", already)
	}
}
