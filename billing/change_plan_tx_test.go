package billing

import (
	"context"
	"errors"
	"testing"
)

type fakeTx struct {
	fakeQS
	begun, commits int
}

func (t *fakeTx) Commit(context.Context) error   { t.commits++; return nil }
func (t *fakeTx) Rollback(context.Context) error { return nil }

func TestChangePlanTx_RunsOnCallerTx(t *testing.T) {
	svc, qs := newSvc(map[string][][]any{
		qLcPlanPolicy: {{"A", int64(14)}},
		qLcPlanPrice:  {{int64(9900), "USD"}},
	})
	tx := &fakeTx{rows: map[string][][]any{qLcChangePlanCurrent: {{"sub_1", "STANDARD"}}}}
	err := svc.ChangePlanTx(context.Background(), tx, 7, "PRO", BillingTerms{BillingCycle: PeriodAnnual, TermType: PeriodAnnual, TermCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	if args := lastCall(t, qs, qLcPlanPrice).args; args[1] != "A" || args[2] != "A" {
		t.Fatalf("price args = %+v", args)
	}
	// Price read stays on the service qs; writes run on the caller's tx.
	lastCall(t, qs, qLcPlanPrice)
	lastCall(t, &tx.fakeQS, qLcChangePlanCurrent)
	lastCall(t, &tx.fakeQS, qLcChangePlanClose)
	ins := lastCall(t, &tx.fakeQS, qLcInsertActive)
	if ins.args[0] != int64(7) || ins.args[1] != "PRO" || ins.args[10] != "sub_1" || ins.args[4] != "A" {
		t.Fatalf("insert args = %+v", ins.args)
	}
	if len(qs.calls) > 0 {
		for _, c := range qs.calls {
			if c.name == qLcChangePlanCurrent || c.name == qLcChangePlanClose || c.name == qLcInsertActive {
				t.Fatalf("write %q ran outside the caller tx", c.name)
			}
		}
	}
}

func TestChangePlanTx_RejectsInactivePlanBeforeWrites(t *testing.T) {
	svc, _ := newSvc(nil)
	tx := &fakeTx{}
	err := svc.ChangePlanTx(context.Background(), tx, 7, "RETIRED", BillingTerms{})
	if !errors.Is(err, ErrPlanNotFound) {
		t.Fatalf("err = %v, want ErrPlanNotFound", err)
	}
	if len(tx.calls) != 0 {
		t.Fatalf("transaction calls = %+v", tx.calls)
	}
}
