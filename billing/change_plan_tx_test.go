package billing

import (
	"context"
	"errors"
	"testing"
)

type fakeTx struct{ fakeQS }

func (t *fakeTx) Commit(context.Context) error   { return nil }
func (t *fakeTx) Rollback(context.Context) error { return nil }

func TestChangePlanTx_RunsOnCallerTx(t *testing.T) {
	svc, qs := newSvc(map[string][][]any{
		qLcPlanPolicy: {{"A", int64(14)}},
		qLcPlanPrice:  {{int64(9900), "USD"}},
	})
	tx := &fakeTx{fakeQS{rows: map[string][][]any{qLcChangePlanCurrent: {{"sub_1"}}}}}
	err := svc.ChangePlanTx(context.Background(), tx, 7, "PRO", BillingTerms{})
	if err != nil {
		t.Fatal(err)
	}
	// Price read stays on the service qs; writes run on the caller's tx.
	lastCall(t, qs, qLcPlanPrice)
	lastCall(t, &tx.fakeQS, qLcChangePlanCurrent)
	lastCall(t, &tx.fakeQS, qLcChangePlanClose)
	ins := lastCall(t, &tx.fakeQS, qLcInsertActive)
	if ins.args[0] != int64(7) || ins.args[1] != "PRO" || ins.args[10] != "sub_1" {
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
