package billing

import (
	"strings"
	"testing"

	"github.com/nauticana/keel/port"
)

func TestOverTargetLimitErrorNamesCaption(t *testing.T) {
	err := &OverTargetLimitError{PlanID: "STANDARD", Overages: []port.QuotaOverage{
		{Resource: "MAX_LOCATIONS", Caption: "Locations", Count: 3, Limit: 1},
		{Resource: "KEYWORDS", Count: 250, Limit: 200},
	}}
	if msg := err.Error(); !strings.Contains(msg, "Locations 3 of 1") || !strings.Contains(msg, "KEYWORDS 250 of 200") {
		t.Fatalf("message = %q", msg)
	}
}
