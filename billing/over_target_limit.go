package billing

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nauticana/keel/port"
)

// ErrOverTargetLimit refuses a change to a plan whose limits are below what
// the partner already holds; errors.As an *OverTargetLimitError for the list.
var ErrOverTargetLimit = errors.New("partner holds more than the plan allows")

// OverTargetLimitError lists what the partner must remove before moving to PlanID.
type OverTargetLimitError struct {
	PlanID   string
	Overages []port.QuotaOverage
}

func (e *OverTargetLimitError) Error() string {
	parts := make([]string, len(e.Overages))
	for i, o := range e.Overages {
		name := o.Caption
		if name == "" {
			name = o.Resource
		}
		parts[i] = fmt.Sprintf("%s %d of %d", name, o.Count, o.Limit)
	}
	return fmt.Sprintf("%s: plan %s (%s)", ErrOverTargetLimit, e.PlanID, strings.Join(parts, ", "))
}

func (e *OverTargetLimitError) Is(target error) bool { return target == ErrOverTargetLimit }
