package user

import (
	"github.com/nauticana/keel/billing"
)

// PublicPlan is the unauthenticated registration-page view of a plan. Prices is
// the same per-offer shape as billing.GetPlans so the shared sail price selector
// works without auth.
type PublicPlan struct {
	ID             string              `json:"id"`
	Caption        string              `json:"caption"`
	ActivationMode string              `json:"activationMode"` // drives the registration CTA (trial vs subscribe)
	TrialDays      int                 `json:"trialDays"`
	Prices         []billing.PlanPrice `json:"prices"`
}
