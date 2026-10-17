package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/payment"
)

var succBegda = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// newSuccSvc wires a service whose catalog reports mode for every plan and
// whose transaction replays txRows.
func newSuccSvc(rows map[string][][]any, mode string, txRows map[string][][]any) (*AbstractBillingService, *fakeQS, *fakeTx) {
	if rows == nil {
		rows = map[string][][]any{}
	}
	rows[qLcPlanPolicy] = [][]any{{mode, int64(14)}}
	qs := &fakeQS{rows: rows}
	tx := &fakeTx{fakeQS: fakeQS{rows: txRows}}
	return &AbstractBillingService{Repo: fakeRepo{qs: qs, tx: tx}, FallbackPlanID: "FREE"}, qs, tx
}

func callCount(qs *fakeQS, name string) int {
	n := 0
	for _, c := range qs.calls {
		if c.name == name {
			n++
		}
	}
	return n
}

func TestCancelByProviderSubID_StartsNextPlan(t *testing.T) {
	ended := map[string][][]any{qLcEndRow: {{int64(7)}}, qLcInsertFree: {{"FREE"}}}
	for _, tc := range []struct {
		name, successor, planMode, wantStart string
	}{
		{name: "paid plan falls back", planMode: "A", wantStart: "FREE"},
		{name: "scheduled successor wins", successor: "BASIC", planMode: "A", wantStart: "BASIC"},
		{name: "free plan has no fallback", planMode: "F"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, tx := newSuccSvc(map[string][][]any{
				qLcLiveByProviderSub: {{int64(7), "PRO", succBegda, tc.successor, tc.planMode}},
			}, "F", ended)
			n, err := svc.CancelByProviderSubID(context.Background(), "sub_1", CancelImmediate)
			if err != nil || n != 1 || tx.commits != 1 {
				t.Fatalf("n=%d err=%v commits=%d", n, err, tx.commits)
			}
			end := lastCall(t, &tx.fakeQS, qLcEndRow)
			if end.args[0] != int64(7) || end.args[1] != "PRO" || end.args[2] != succBegda {
				t.Fatalf("end args = %v", end.args)
			}
			if tc.wantStart == "" {
				if callCount(&tx.fakeQS, qLcInsertFree) != 0 {
					t.Fatal("started a plan after a free plan ended")
				}
				return
			}
			ins := lastCall(t, &tx.fakeQS, qLcInsertFree)
			if ins.args[0] != int64(7) || ins.args[1] != tc.wantStart || ins.args[2] != int64(7) {
				t.Fatalf("insert args = %v", ins.args)
			}
		})
	}
}

func TestCancelByProviderSubID_AlreadyEndedStartsNothing(t *testing.T) {
	svc, _, tx := newSuccSvc(map[string][][]any{
		qLcLiveByProviderSub: {{int64(7), "PRO", succBegda, "", "A"}},
	}, "F", nil)
	n, err := svc.CancelByProviderSubID(context.Background(), "sub_1", CancelImmediate)
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if callCount(&tx.fakeQS, qLcInsertFree) != 0 {
		t.Fatal("a row another caller ended started a second plan")
	}
}

// The row ends even when its next plan cannot start: a partner never keeps a
// subscription the provider already ended. The succession failure is returned.
func TestCancel_EndsRowWhenFallbackIsNotFree(t *testing.T) {
	svc, _, tx := newSuccSvc(map[string][][]any{
		qLcLiveByPartner: {{int64(7), "PRO", succBegda, "", "A"}},
	}, "A", map[string][][]any{qLcEndRow: {{int64(7)}}})
	if err := svc.CancelSubscription(context.Background(), 7); !errors.Is(err, ErrNotFreePlan) {
		t.Fatalf("err = %v, want ErrNotFreePlan", err)
	}
	if tx.commits != 1 || callCount(&tx.fakeQS, qLcEndRow) != 1 || callCount(&tx.fakeQS, qLcInsertFree) != 0 {
		t.Fatalf("commits=%d calls=%+v", tx.commits, tx.calls)
	}
}

// A pending row blocks the free row; the end still commits and the block is reported.
func TestCancel_ReportsBlockedSuccessor(t *testing.T) {
	svc, _, tx := newSuccSvc(map[string][][]any{
		qLcLiveByProviderSub: {{int64(7), "PRO", succBegda, "", "A"}},
	}, "F", map[string][][]any{qLcEndRow: {{int64(7)}}})
	n, err := svc.CancelByProviderSubID(context.Background(), "sub_1", CancelImmediate)
	if n != 1 || !errors.Is(err, ErrSubscriptionPending) || tx.commits != 1 {
		t.Fatalf("n=%d err=%v commits=%d", n, err, tx.commits)
	}
}

func TestChangePlanTx_FreePlanRefusesProviderHeldRow(t *testing.T) {
	svc, _, _ := newSuccSvc(nil, "F", nil)
	tx := &fakeTx{fakeQS: fakeQS{rows: map[string][][]any{qLcChangePlanCurrent: {{"sub_1", "PRO"}}, qLcInsertFree: {{"FREE"}}}}}
	if err := svc.ChangePlanTx(context.Background(), tx, 7, "FREE", BillingTerms{}); !errors.Is(err, ErrProviderSubscription) {
		t.Fatalf("err = %v, want ErrProviderSubscription", err)
	}
	if callCount(&tx.fakeQS, qLcChangePlanClose) != 0 || callCount(&tx.fakeQS, qLcInsertFree) != 0 {
		t.Fatalf("wrote past a provider-held row: %+v", tx.calls)
	}
}

func TestResumeRenewal(t *testing.T) {
	svc, qs, _ := newSuccSvc(nil, "F", nil)
	if err := svc.ResumeRenewal(context.Background(), 7); err != nil {
		t.Fatal(err)
	}
	if args := lastCall(t, qs, qLcResumeRenewal).args; args[0] != int64(7) {
		t.Fatalf("args = %v", args)
	}
}

func TestCancelByPartner_PeriodEndClearsSuccessor(t *testing.T) {
	svc, qs, tx := newSuccSvc(nil, "F", nil)
	if err := svc.CancelByPartner(context.Background(), 7, CancelAtPeriodEnd); err != nil {
		t.Fatal(err)
	}
	lastCall(t, qs, qLcCancelPartnerPeriodEnd)
	if tx.begun != 0 {
		t.Fatal("period-end cancel ended the row now")
	}
}

func TestEndDue(t *testing.T) {
	svc, qs, tx := newSuccSvc(map[string][][]any{
		qLcDueToEnd: {
			{int64(7), "PRO", succBegda, "", "A"},
			{int64(8), "PRO", succBegda, "", "A"},
		},
	}, "F", map[string][][]any{qLcEndRow: {{int64(1)}}, qLcInsertFree: {{"FREE"}}})
	n, err := svc.EndDue(context.Background(), 50)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if tx.begun != 2 || tx.commits != 2 || callCount(&tx.fakeQS, qLcInsertFree) != 2 {
		t.Fatalf("begun=%d commits=%d", tx.begun, tx.commits)
	}
	if callCount(qs, qLcPlanPolicy) != 1 {
		t.Fatalf("plan policy read %d times for one fallback plan", callCount(qs, qLcPlanPolicy))
	}
	if args := lastCall(t, qs, qLcDueToEnd).args; args[0] != 50 {
		t.Fatalf("limit arg = %v", args)
	}
	if _, err := svc.EndDue(context.Background(), 0); err == nil {
		t.Fatal("EndDue accepted a zero limit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := svc.EndDue(ctx, 50); !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatalf("cancelled: n=%d err=%v", n, err)
	}
}

// A row whose successor cannot start does not hold the rest of the sweep back.
func TestEndDue_ContinuesPastFailingRow(t *testing.T) {
	svc, _, tx := newSuccSvc(map[string][][]any{
		qLcDueToEnd: {
			{int64(5), "PRO", succBegda, "PAID", "A"},
			{int64(6), "PRO", succBegda, "", "A"},
		},
	}, "F", map[string][][]any{qLcEndRow: {{int64(1)}}, qLcInsertFree: {{"FREE"}}})
	svc.Repo.(fakeRepo).qs.(*fakeQS).rowsFor = func(name string, args []any) ([][]any, bool) {
		if name == qLcPlanPolicy && args[0] == "PAID" {
			return [][]any{{"A", int64(14)}}, true
		}
		return nil, false
	}
	n, err := svc.EndDue(context.Background(), 50)
	if n != 2 || !errors.Is(err, ErrNotFreePlan) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if tx.commits != 2 || callCount(&tx.fakeQS, qLcInsertFree) != 1 {
		t.Fatalf("commits=%d inserts=%d", tx.commits, callCount(&tx.fakeQS, qLcInsertFree))
	}
	if ins := lastCall(t, &tx.fakeQS, qLcInsertFree); ins.args[0] != int64(6) {
		t.Fatalf("free row started for partner %v, want 6", ins.args[0])
	}
}

func TestScheduleChange(t *testing.T) {
	paid, _, _ := newSuccSvc(nil, "A", nil)
	if err := paid.ScheduleChange(context.Background(), 7, "PRO"); !errors.Is(err, ErrNotFreePlan) {
		t.Fatalf("paid successor: err = %v", err)
	}
	none, _, _ := newSuccSvc(nil, "F", nil)
	if err := none.ScheduleChange(context.Background(), 7, "FREE"); !errors.Is(err, ErrNoSubscription) {
		t.Fatalf("no subscription: err = %v", err)
	}
	svc, qs, _ := newSuccSvc(map[string][][]any{qLcScheduleChange: {{int64(7)}}}, "F", nil)
	if err := svc.ScheduleChange(context.Background(), 7, "FREE"); err != nil {
		t.Fatal(err)
	}
	if args := lastCall(t, qs, qLcScheduleChange).args; args[0] != "FREE" || args[1] != int64(7) {
		t.Fatalf("args = %v", args)
	}
}

func TestChangePlanTx_FreePlan(t *testing.T) {
	svc, qs, _ := newSuccSvc(nil, "F", nil)
	tx := &fakeTx{fakeQS: fakeQS{rows: map[string][][]any{qLcInsertFree: {{"FREE"}}}}}
	if err := svc.ChangePlanTx(context.Background(), tx, 7, "FREE", BillingTerms{}); err != nil {
		t.Fatal(err)
	}
	lastCall(t, &tx.fakeQS, qLcChangePlanClose)
	lastCall(t, &tx.fakeQS, qLcInsertFree)
	if callCount(qs, qLcPlanPrice) != 0 || callCount(&tx.fakeQS, qLcInsertActive) != 0 {
		t.Fatal("free plan change read a price or wrote a priced row")
	}

	pending := &fakeTx{}
	if err := svc.ChangePlanTx(context.Background(), pending, 7, "FREE", BillingTerms{}); !errors.Is(err, ErrSubscriptionPending) {
		t.Fatalf("pending subscription: err = %v", err)
	}
}

func TestSubscriptionCanceledEventEndsOnlyNamedSubscription(t *testing.T) {
	cancelled := &payment.PaymentEvent{
		EventKind:      payment.KindSubscriptionCanceled,
		SubscriptionID: "sub_old",
		Metadata:       map[string]string{"partner_id": "7"},
	}

	svc, qs, tx := newSuccSvc(map[string][][]any{
		qLcLiveByProviderSub: {{int64(7), "PRO", succBegda, "", "A"}},
	}, "F", map[string][][]any{qLcEndRow: {{int64(7)}}, qLcInsertFree: {{"FREE"}}})
	h := NewProviderSubscriptionEventHandler(svc, svc, SubscriptionHandlerOptions{})
	if err := h.OnPaymentEvent(context.Background(), cancelled); err != nil || tx.commits != 1 {
		t.Fatalf("err=%v commits=%d", err, tx.commits)
	}
	if callCount(qs, qLcLiveByPartner) != 0 {
		t.Fatal("a named subscription ended the partner's current plan")
	}

	// No live row for the named subscription: the mismatch is an error, not a
	// silent success, so the webhook log shows it.
	unknown, unknownQS, unknownTx := newSuccSvc(nil, "F", nil)
	h = NewProviderSubscriptionEventHandler(unknown, unknown, SubscriptionHandlerOptions{})
	if err := h.OnPaymentEvent(context.Background(), cancelled); !errors.Is(err, ErrUnknownSubscription) {
		t.Fatalf("err = %v, want ErrUnknownSubscription", err)
	}
	if callCount(unknownQS, qLcLiveByPartner) != 0 || unknownTx.begun != 0 {
		t.Fatal("cancellation of an unknown subscription ended the partner's current plan")
	}
}
