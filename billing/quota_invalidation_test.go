package billing

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/port"
)

type recordingQuotas struct {
	port.QuotaService
	partners []int64
}

func (q *recordingQuotas) InvalidatePartner(_ context.Context, partnerID int64) {
	q.partners = append(q.partners, partnerID)
}

// Every committed change of the active plan drops the partner's cached
// limits, so a downgrade is enforced at once.
func TestLifecycleInvalidatesQuotas(t *testing.T) {
	ctx := context.Background()
	for name, run := range map[string]func(*AbstractBillingService) error{
		"activate": func(s *AbstractBillingService) error {
			return s.Activate(ctx, 7, "STANDARD", BillingTerms{}, "sub_1", 0)
		},
		"change plan": func(s *AbstractBillingService) error {
			return s.ChangePlan(ctx, 7, "STANDARD", BillingTerms{})
		},
		"create": func(s *AbstractBillingService) error {
			return s.CreateSubscription(ctx, 7, "STANDARD", BillingTerms{})
		},
		"provider cancel": func(s *AbstractBillingService) error {
			_, err := s.CancelByProviderSubID(ctx, "sub_1", CancelImmediate)
			return err
		},
		"partner cancel": func(s *AbstractBillingService) error {
			return s.CancelByPartner(ctx, 7, CancelImmediate)
		},
		"end due": func(s *AbstractBillingService) error {
			_, err := s.EndDue(ctx, 10)
			return err
		},
		"convert trial": func(s *AbstractBillingService) error { return s.ConvertTrial(ctx, 7, "sub_1") },
		"dunning":       func(s *AbstractBillingService) error { return s.SetDunningState(ctx, 7, "sub_1", "X") },
		"reactivate":    func(s *AbstractBillingService) error { return s.Reactivate(ctx, 7, "STANDARD") },
	} {
		t.Run(name, func(t *testing.T) {
			live := [][]any{{int64(7), "PRO", succBegda, "", "A"}}
			svc, _, _ := newTxSvc(map[string][][]any{
				qLcPlanPolicy:        {{"A", int64(14)}},
				qLcPlanPrice:         {{int64(10000), "USD"}},
				qLcLiveByProviderSub: live,
				qLcLiveByPartner:     live,
				qLcDueToEnd:          live,
			}, map[string][][]any{qLcEndRow: {{int64(7)}}, qLcChangePlanCurrent: {{""}}})
			quotas := &recordingQuotas{}
			svc.Quotas = quotas
			if err := run(svc); err != nil {
				t.Fatal(err)
			}
			if len(quotas.partners) == 0 || quotas.partners[0] != 7 {
				t.Fatalf("invalidated %v, want partner 7", quotas.partners)
			}
		})
	}
}

func TestRefusedActivationInvalidatesNothing(t *testing.T) {
	svc, _, _ := newTxSvc(map[string][][]any{
		qLcPlanPolicy: {{"A", int64(14)}},
		qLcPlanPrice:  {{int64(10000), "USD"}},
	}, map[string][][]any{qLcPartnerRows: {{"PRO", succBegda, "A", "sub_other", "A"}}})
	quotas := &recordingQuotas{}
	svc.Quotas = quotas
	if err := svc.Activate(context.Background(), 7, "STANDARD", BillingTerms{}, "sub_1", 0); !errors.Is(err, ErrSubscriptionActive) {
		t.Fatalf("err = %v", err)
	}
	if len(quotas.partners) != 0 {
		t.Fatalf("refused activation invalidated %v", quotas.partners)
	}
}
