package billing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

type fakeCall struct {
	name string
	args []any
}

// fakeQS records every Query call and replays canned rows per query name.
type fakeQS struct {
	calls []fakeCall
	rows  map[string][][]any
	// rowsFor, when set, answers a query from its arguments before rows is consulted.
	rowsFor func(name string, args []any) ([][]any, bool)
	id      int64
}

func (q *fakeQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	q.calls = append(q.calls, fakeCall{name, args})
	if q.rowsFor != nil {
		if rows, ok := q.rowsFor(name, args); ok {
			return &model.QueryResult{Rows: rows}, nil
		}
	}
	return &model.QueryResult{Rows: q.rows[name]}, nil
}
func (q *fakeQS) GenID() int64 { q.id++; return q.id }

// fakeRepo satisfies data.DatabaseRepository by embedding it; only
// GetQueryService is exercised (any other call would nil-panic, by design).
type fakeRepo struct {
	port.DatabaseRepository
	qs port.QueryService
	tx *fakeTx
}

func (r fakeRepo) GetQueryService(context.Context, map[string]string) port.QueryService { return r.qs }
func (r fakeRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	if r.tx == nil {
		return nil, errors.New("fakeRepo: no transaction configured")
	}
	r.tx.begun++
	return r.tx, nil
}

func newSvc(rows map[string][][]any) (*AbstractBillingService, *fakeQS) {
	svc, qs, _ := newTxSvc(rows, nil)
	return svc, qs
}

// newTxSvc is newSvc whose transactions replay txRows and record their writes.
func newTxSvc(rows, txRows map[string][][]any) (*AbstractBillingService, *fakeQS, *fakeTx) {
	qs := &fakeQS{rows: rows}
	tx := &fakeTx{fakeQS: fakeQS{rows: txRows}}
	return &AbstractBillingService{Repo: fakeRepo{qs: qs, tx: tx}}, qs, tx
}

func lastCall(t *testing.T, qs *fakeQS, name string) fakeCall {
	t.Helper()
	for i := len(qs.calls) - 1; i >= 0; i-- {
		if qs.calls[i].name == name {
			return qs.calls[i]
		}
	}
	t.Fatalf("query %q was not executed; calls=%+v", name, qs.calls)
	return fakeCall{}
}

func TestRecordProviderInvoice_SkipsWithoutInvoiceID(t *testing.T) {
	svc, qs := newSvc(nil)
	if err := svc.RecordProviderInvoice(context.Background(), 7, &payment.PaymentEvent{}); err != nil {
		t.Fatal(err)
	}
	if len(qs.calls) != 0 {
		t.Fatalf("expected no query for empty InvoiceID, got %+v", qs.calls)
	}
}

func TestRecordProviderInvoice_WritesRow(t *testing.T) {
	svc, qs := newSvc(nil)
	paid := time.Now().UTC()
	e := &payment.PaymentEvent{InvoiceID: "in_123", MinorUnits: 1999, Currency: "USD", PaidAt: paid}
	if err := svc.RecordProviderInvoice(context.Background(), 7, e); err != nil {
		t.Fatal(err)
	}
	c := lastCall(t, qs, qBillRecordInvoice)
	// args: id, partner, number, subtotal_minor, total_minor, currency, paid_at, provider_invoice_id
	if len(c.args) != 8 {
		t.Fatalf("want 8 args, got %d: %v", len(c.args), c.args)
	}
	if c.args[1] != int64(7) || c.args[2] != "in_123" || c.args[3] != int64(1999) || c.args[4] != int64(1999) || c.args[5] != "USD" || c.args[7] != "in_123" {
		t.Fatalf("bad args: %v", c.args)
	}
	if c.args[6] != paid {
		t.Fatalf("paid_at mismatch: %v", c.args[6])
	}
}

func TestLinkCustomer(t *testing.T) {
	svc, qs := newSvc(nil)
	if err := svc.LinkCustomer(context.Background(), 7, "stripe", ""); err != nil {
		t.Fatal(err)
	}
	if len(qs.calls) != 0 {
		t.Fatalf("empty token should be a no-op; got %+v", qs.calls)
	}
	if err := svc.LinkCustomer(context.Background(), 7, "stripe", "cus_9"); err != nil {
		t.Fatal(err)
	}
	c := lastCall(t, qs, qBillLinkCustomer)
	// args: partner, provider, token (INSERT … VALUES(?,?,?) ON CONFLICT DO NOTHING)
	if c.args[0] != int64(7) || c.args[1] != "stripe" || c.args[2] != "cus_9" {
		t.Fatalf("bad args: %v", c.args)
	}
}

func TestCustomerToken(t *testing.T) {
	svc, _ := newSvc(map[string][][]any{qBillCustomerToken: {{"cus_42"}}})
	got, err := svc.CustomerToken(context.Background(), 7, "stripe")
	if err != nil || got != "cus_42" {
		t.Fatalf("got %q err %v", got, err)
	}
	empty, _ := newSvc(nil)
	got, err = empty.CustomerToken(context.Background(), 7, "stripe")
	if err != nil || got != "" {
		t.Fatalf("want empty, got %q err %v", got, err)
	}
}

func TestPartnerByCustomer(t *testing.T) {
	svc, _ := newSvc(map[string][][]any{qBillPartnerByCust: {{int64(55)}}})
	got, err := svc.PartnerByCustomer(context.Background(), "stripe", "cus_42")
	if err != nil || got != 55 {
		t.Fatalf("got %d err %v", got, err)
	}
}

// fixedClock returns a deterministic Now for renewal/trial math.
func fixedClock() func() time.Time {
	t := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// insertActive arg indexes (qLcInsertActive bind order).
const (
	iaCost = 2 + iota // perChargeMajor
	iaCurrency
	iaBillingCycle
	iaTermCount
	iaTermType
	iaAmountMinor
	iaRenewal
	iaNextCharge
	iaProviderSub
	iaSeats
)

func TestActivate_MonthlyCreateActive(t *testing.T) {
	// policy: mode=A, trial_days=14. price row: $100/month (term_type=M, 10000 minor).
	svc, qs, tx := newTxSvc(map[string][][]any{
		qLcPlanPolicy: {{"A", int64(14)}},
		qLcPlanPrice:  {{int64(10000), "USD"}},
	}, nil)
	svc.Now = fixedClock()
	terms := BillingTerms{PeriodMonthly, PeriodMonthly, 1}
	if err := svc.Activate(context.Background(), 7, "pro", terms, "sub_1", 3); err != nil {
		t.Fatal(err)
	}
	// price lookup keyed by (plan, billing_cycle, term_type, term_count)
	pc := lastCall(t, qs, qLcPlanPrice)
	if pc.args[0] != "pro" || pc.args[1] != "M" || pc.args[2] != "M" || pc.args[3] != 1 {
		t.Fatalf("price lookup args = %v", pc.args)
	}
	c := lastCall(t, &tx.fakeQS, qLcInsertActive)
	want := map[int]any{
		0: int64(7), 1: "pro",
		iaCost: int64(10000), iaCurrency: "USD", iaBillingCycle: "M",
		iaTermCount: int64(1), iaTermType: "M", iaAmountMinor: int64(10000),
		iaRenewal:     time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC), // +1 month term
		iaNextCharge:  time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC), // due now
		iaProviderSub: "sub_1", iaSeats: int64(3),
	}
	for i, w := range want {
		if c.args[i] != w {
			t.Fatalf("arg[%d] = %#v, want %#v", i, c.args[i], w)
		}
	}
}

// The headline case: $1000/yr billed monthly → $83.33/charge, term ends +1yr.
func TestActivate_AnnualPaidMonthly(t *testing.T) {
	svc, _, tx := newTxSvc(map[string][][]any{
		qLcPlanPolicy: {{"A", int64(14)}},
		qLcPlanPrice:  {{int64(100000), "USD"}}, // $1000 per year (term_type=A)
	}, nil)
	svc.Now = fixedClock()
	terms := BillingTerms{PeriodMonthly, PeriodAnnual, 1}
	if err := svc.Activate(context.Background(), 7, "pro", terms, "sub_1", 0); err != nil {
		t.Fatal(err)
	}
	c := lastCall(t, &tx.fakeQS, qLcInsertActive)
	if c.args[iaBillingCycle] != "M" || c.args[iaTermType] != "A" {
		t.Fatalf("billing M / term A expected: %v", c.args)
	}
	if c.args[iaAmountMinor] != int64(100000) {
		t.Fatalf("per-unit amount snapshot 100000 expected, got %#v", c.args[iaAmountMinor])
	}
	if c.args[iaCost] != int64(8333) { // 100000/12 floored
		t.Fatalf("per-charge should be 8333, got %#v", c.args[iaCost])
	}
	if c.args[iaRenewal] != time.Date(2027, 6, 8, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("term end should be +1 year, got %#v", c.args[iaRenewal])
	}
	if c.args[iaSeats] != nil {
		t.Fatalf("seats<=0 should bind nil, got %#v", c.args[iaSeats])
	}
}

func TestActivate_TrialAnchorsTermAtTrialEnd(t *testing.T) {
	svc, _, tx := newTxSvc(map[string][][]any{
		qLcPlanPolicy: {{"T", int64(30)}},
		qLcPlanPrice:  {{int64(100000), "USD"}},
	}, nil)
	svc.Now = fixedClock()
	if err := svc.Activate(context.Background(), 7, "pro", BillingTerms{PeriodMonthly, PeriodAnnual, 1}, "sub_1", 0); err != nil {
		t.Fatal(err)
	}
	c := lastCall(t, &tx.fakeQS, qLcStartTrial)
	// trial bind order: ...,trial_end(8), renewal(9), next_charge(10)
	trialEnd := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC) // now + 30 days
	if c.args[8] != trialEnd {
		t.Fatalf("trial_end should be now+trial_days, got %#v", c.args[8])
	}
	if c.args[9] != trialEnd.AddDate(1, 0, 0) { // term starts at trial end
		t.Fatalf("renewal should be trial_end + term, got %#v", c.args[9])
	}
	if c.args[10] != trialEnd { // first charge when trial ends
		t.Fatalf("next_charge should be trial_end, got %#v", c.args[10])
	}
}

func TestActivate_UnknownPlan(t *testing.T) {
	svc, _ := newSvc(nil) // qLcPlanPolicy returns no rows
	err := svc.Activate(context.Background(), 7, "ghost", BillingTerms{PeriodMonthly, PeriodMonthly, 1}, "", 0)
	if err == nil || !errors.Is(err, ErrPlanNotFound) {
		t.Fatalf("want ErrPlanNotFound, got %v", err)
	}
}

func TestActivate_OfferNotOffered(t *testing.T) {
	// plan exists, but no price row for the chosen (cycle, term).
	svc, _ := newSvc(map[string][][]any{
		qLcPlanPolicy: {{"A", int64(14)}},
	})
	err := svc.Activate(context.Background(), 7, "pro", BillingTerms{PeriodMonthly, PeriodAnnual, 1}, "", 0)
	if err == nil || !errors.Is(err, ErrPriceNotFound) {
		t.Fatalf("want ErrPriceNotFound, got %v", err)
	}
}

func TestGetPlans_GroupsPricesByPlan(t *testing.T) {
	// rows: id, caption, currency, activation_mode, trial_days, billing_cycle, term_count, term_type, amount_minor, currency, provider_price_id, exponent
	svc, _ := newSvc(map[string][][]any{
		qBillGetAllPlans: {
			{"pro", "Pro", "USD", "A", int64(14), "M", int64(1), "M", int64(10000), "USD", "price_m", int64(2)},
			{"pro", "Pro", "BHD", "A", int64(14), "A", int64(1), "A", int64(100000), "BHD", "price_a", int64(3)},
			{"free", "Free", "USD", "F", nil, "", nil, nil, nil, nil, nil, nil}, // LEFT JOIN, no price
		},
	})
	plans, err := svc.GetPlans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("want 2 plans, got %d", len(plans))
	}
	pro := plans[0]
	if pro.ID != "pro" || len(pro.Prices) != 2 {
		t.Fatalf("pro should have 2 prices: %+v", pro)
	}
	if pro.Prices[0].AmountMinor != 10000 || pro.Prices[0].TermType != "M" || pro.Prices[0].Amount != 100 || pro.Prices[0].Exponent != 2 {
		t.Fatalf("monthly price row wrong: %+v", pro.Prices[0])
	}
	if pro.Prices[1].AmountMinor != 100000 || pro.Prices[1].TermType != "A" || pro.Prices[1].Amount != 100 || pro.Prices[1].Exponent != 3 {
		t.Fatalf("annual price row wrong: %+v", pro.Prices)
	}
	if free := plans[1]; free.ID != "free" || len(free.Prices) != 0 {
		t.Fatalf("free should have no prices: %+v", free)
	}
}

func TestListPaymentMethods(t *testing.T) {
	svc, _ := newSvc(map[string][][]any{qBillListMethods: {
		{int64(900719925474099300), "stripe", "customer", true},
		{int64(2), "stripe", "card", false},
	}})
	got, err := svc.ListPaymentMethods(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 rows, got %d", len(got))
	}
	if got[0].ID != "900719925474099300" || !got[0].IsDefault || got[0].MethodType != "customer" {
		t.Fatalf("row0 mismatch: %+v", got[0])
	}
	if got[1].ID != "2" || got[1].IsDefault || got[1].MethodType != "card" {
		t.Fatalf("row1 mismatch: %+v", got[1])
	}
}

func TestInvoiceIDSerializesAsString(t *testing.T) {
	b, err := json.Marshal(Invoice{ID: 1<<60 + 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"id":"1152921504606846977"`) {
		t.Fatalf("invoice json = %s", b)
	}
}

func TestGetUsage_CaptionUsedAndLimit(t *testing.T) {
	svc, qs := newSvc(map[string][][]any{qBillGetUsage: {{"AI credits", int64(12), int64(100)}}})
	svc.ResourceNames = []string{"AI_CREDITS"}
	items, err := svc.GetUsage(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0] != (UsageItem{Resource: "AI_CREDITS", Caption: "AI credits", Used: 12, Limit: 100}) {
		t.Fatalf("items=%+v", items)
	}
	if args := lastCall(t, qs, qBillGetUsage).args; args[0] != int64(7) || args[2] != int64(7) || args[3] != "AI_CREDITS" {
		t.Fatalf("args=%v", args)
	}
}

func TestGetUsage_UnknownResource(t *testing.T) {
	svc, _ := newSvc(nil)
	svc.ResourceNames = []string{"MISSING"}
	if _, err := svc.GetUsage(context.Background(), 7); !errors.Is(err, ErrUnknownResource) {
		t.Fatalf("err=%v, want ErrUnknownResource", err)
	}
}

func TestGetSubscription_ProviderManaged(t *testing.T) {
	for _, managed := range []bool{true, false} {
		svc, _ := newSvc(map[string][][]any{qBillGetSubscription: {{
			"PRO", "Pro", "A", "2026-01-01", nil, int64(999), "USD", "M", true, nil, int32(1), int64(2), managed, nil, "", "A",
		}}})
		sub, err := svc.GetSubscription(context.Background(), 7)
		if err != nil {
			t.Fatal(err)
		}
		if sub.ProviderManaged != managed || !sub.AutoRenew {
			t.Fatalf("managed=%v autoRenew=%v, want %v true", sub.ProviderManaged, sub.AutoRenew, managed)
		}
	}
}

func TestGetSubscription_ScheduledChange(t *testing.T) {
	for _, tc := range []struct {
		name, successor, mode, fallback, wantPlan, wantAt string
		ends                                              any
	}{
		{name: "not ending", mode: "A", fallback: "FREE"},
		{name: "successor", ends: "2026-11-12", successor: "BASIC", mode: "A", fallback: "FREE", wantPlan: "BASIC", wantAt: "2026-11-12"},
		{name: "paid falls back", ends: "2026-11-12", mode: "A", fallback: "FREE", wantPlan: "FREE", wantAt: "2026-11-12"},
		{name: "free does not fall back", ends: "2026-11-12", mode: "F", fallback: "FREE", wantAt: "2026-11-12"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newSvc(map[string][][]any{qBillGetSubscription: {{
				"PRO", "Pro", "A", "2026-01-01", nil, int64(999), "USD", "M", false, nil, int32(1), int64(2), true, tc.ends, tc.successor, tc.mode,
			}}})
			svc.FallbackPlanID = tc.fallback
			sub, err := svc.GetSubscription(context.Background(), 7)
			if err != nil {
				t.Fatal(err)
			}
			if sub.ScheduledPlanID != tc.wantPlan || sub.ScheduledAt != tc.wantAt {
				t.Fatalf("scheduled = %q at %q, want %q at %q", sub.ScheduledPlanID, sub.ScheduledAt, tc.wantPlan, tc.wantAt)
			}
		})
	}
}

var activateBegda = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func activationSvc(mode string, txRows map[string][][]any) (*AbstractBillingService, *fakeTx) {
	svc, _, tx := newTxSvc(map[string][][]any{
		qLcPlanPolicy: {{mode, int64(14)}},
		qLcPlanPrice:  {{int64(10000), "USD"}},
	}, txRows)
	svc.Now = fixedClock()
	return svc, tx
}

// A free partner paying for a pending-mode plan has no pending row: the
// checkout opens the paid row and closes the free one in one transaction.
func TestActivate_UpgradeFromFreeWithoutPendingRow(t *testing.T) {
	svc, tx := activationSvc("P", map[string][][]any{
		qLcPartnerRows: {{"FREE", activateBegda, "A", "", "F"}},
	})
	if err := svc.Activate(context.Background(), 7, "STANDARD", BillingTerms{}, "sub_1", 0); err != nil {
		t.Fatal(err)
	}
	if tx.commits != 1 || callCount(&tx.fakeQS, qLcFlipPending) != 0 {
		t.Fatalf("commits=%d calls=%+v", tx.commits, tx.calls)
	}
	end := lastCall(t, &tx.fakeQS, qLcEndRow)
	if end.args[0] != int64(7) || end.args[1] != "FREE" || end.args[2] != activateBegda {
		t.Fatalf("end args = %v", end.args)
	}
	if ins := lastCall(t, &tx.fakeQS, qLcInsertActive); ins.args[1] != "STANDARD" || ins.args[iaProviderSub] != "sub_1" {
		t.Fatalf("insert args = %v", ins.args)
	}
}

func TestActivate_FlipsPendingRow(t *testing.T) {
	svc, tx := activationSvc("P", map[string][][]any{
		qLcPartnerRows: {{"STANDARD", activateBegda, "P", "", "P"}},
		qLcFlipPending: {{int64(7)}},
	})
	if err := svc.Activate(context.Background(), 7, "STANDARD", BillingTerms{}, "sub_1", 0); err != nil {
		t.Fatal(err)
	}
	if tx.commits != 1 || callCount(&tx.fakeQS, qLcInsertActive) != 0 {
		t.Fatalf("commits=%d calls=%+v", tx.commits, tx.calls)
	}
	if flip := lastCall(t, &tx.fakeQS, qLcFlipPending); flip.args[0] != "sub_1" || flip.args[10] != int64(7) || flip.args[11] != "STANDARD" {
		t.Fatalf("flip args = %v", flip.args)
	}
}

// A write that changes nothing is an error, so the webhook is logged as failed.
func TestActivate_PendingFlipThatChangesNothingFails(t *testing.T) {
	svc, tx := activationSvc("P", map[string][][]any{
		qLcPartnerRows: {{"STANDARD", activateBegda, "P", "", "P"}},
	})
	if err := svc.Activate(context.Background(), 7, "STANDARD", BillingTerms{}, "sub_1", 0); err == nil {
		t.Fatal("activation that changed no row reported success")
	}
	if tx.commits != 0 {
		t.Fatal("committed an activation that changed no row")
	}
}

func TestActivate_ExistingPaidSubscription(t *testing.T) {
	replay, replayTx := activationSvc("A", map[string][][]any{
		qLcPartnerRows: {{"STANDARD", activateBegda, "A", "sub_1", "A"}},
	})
	if err := replay.Activate(context.Background(), 7, "STANDARD", BillingTerms{}, "sub_1", 0); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replayTx.commits != 0 || callCount(&replayTx.fakeQS, qLcInsertActive) != 0 {
		t.Fatalf("replay wrote: %+v", replayTx.calls)
	}

	second, secondTx := activationSvc("A", map[string][][]any{
		qLcPartnerRows: {{"STANDARD", activateBegda, "A", "sub_1", "A"}},
	})
	if err := second.Activate(context.Background(), 7, "PRO", BillingTerms{}, "sub_2", 0); !errors.Is(err, ErrSubscriptionActive) {
		t.Fatalf("second paid subscription: err = %v", err)
	}
	if secondTx.commits != 0 || callCount(&secondTx.fakeQS, qLcInsertActive) != 0 || callCount(&secondTx.fakeQS, qLcEndRow) != 0 {
		t.Fatalf("second paid subscription wrote: %+v", secondTx.calls)
	}
}
