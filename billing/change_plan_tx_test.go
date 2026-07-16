package billing

import (
	"context"
	"testing"
)

type fakeTx struct{ fakeQS }

func (t *fakeTx) Commit(context.Context) error   { return nil }
func (t *fakeTx) Rollback(context.Context) error { return nil }

func TestChangePlanTx_RunsOnCallerTx(t *testing.T) {
	svc, qs := newSvc(map[string][][]any{
		qLcPlanPrice: {{int64(9900), "USD"}},
	})
	tx := &fakeTx{}
	err := svc.ChangePlanTx(context.Background(), tx, 7, "PRO", BillingTerms{})
	if err != nil {
		t.Fatal(err)
	}
	// Price read stays on the service qs; writes run on the caller's tx.
	lastCall(t, qs, qLcPlanPrice)
	lastCall(t, &tx.fakeQS, qLcChangePlanClose)
	ins := lastCall(t, &tx.fakeQS, qLcInsertActive)
	if ins.args[0] != int64(7) || ins.args[1] != "PRO" {
		t.Fatalf("insert args = %+v", ins.args[:2])
	}
	if len(qs.calls) > 0 {
		for _, c := range qs.calls {
			if c.name == qLcChangePlanClose || c.name == qLcInsertActive {
				t.Fatalf("write %q ran outside the caller tx", c.name)
			}
		}
	}
}
