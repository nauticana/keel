package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payment"
)

type fakeCall struct {
	name string
	args []any
}

// fakeQS records every Query call and replays canned rows per query name.
type fakeQS struct {
	calls []fakeCall
	rows  map[string][][]any
	id    int64
}

func (q *fakeQS) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	q.calls = append(q.calls, fakeCall{name, args})
	return &model.QueryResult{Rows: q.rows[name]}, nil
}
func (q *fakeQS) GenID() int64 { q.id++; return q.id }

// fakeRepo satisfies data.DatabaseRepository by embedding it; only
// GetQueryService is exercised (any other call would nil-panic, by design).
type fakeRepo struct {
	data.DatabaseRepository
	qs data.QueryService
}

func (r fakeRepo) GetQueryService(context.Context, map[string]string) data.QueryService { return r.qs }

func newSvc(rows map[string][][]any) (*AbstractBillingService, *fakeQS) {
	qs := &fakeQS{rows: rows}
	return &AbstractBillingService{Repo: fakeRepo{qs: qs}}, qs
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
	// args: id, partner, number, subtotal, total, total_minor, currency, paid_at, provider_invoice_id
	if len(c.args) != 9 {
		t.Fatalf("want 9 args, got %d: %v", len(c.args), c.args)
	}
	if c.args[1] != int64(7) || c.args[2] != "in_123" || c.args[5] != int64(1999) || c.args[6] != "USD" || c.args[8] != "in_123" {
		t.Fatalf("bad args: %v", c.args)
	}
	sub, ok1 := c.args[3].(float64)
	tot, ok2 := c.args[4].(float64)
	if !ok1 || !ok2 || sub != tot || sub <= 0 {
		t.Fatalf("major projection should equal subtotal==total>0: %v / %v", c.args[3], c.args[4])
	}
	if c.args[7] != paid {
		t.Fatalf("paid_at mismatch: %v", c.args[7])
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
	svc, qs := newSvc(map[string][][]any{
		qLcPlanPolicy: {{"A", int64(14)}},
		qLcPlanPrice:  {{int64(10000), "USD"}},
	})
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
	c := lastCall(t, qs, qLcInsertActive)
	want := map[int]any{
		0: int64(7), 1: "pro",
		iaCost: 100.0, iaCurrency: "USD", iaBillingCycle: "M",
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
	svc, qs := newSvc(map[string][][]any{
		qLcPlanPolicy: {{"A", int64(14)}},
		qLcPlanPrice:  {{int64(100000), "USD"}}, // $1000 per year (term_type=A)
	})
	svc.Now = fixedClock()
	terms := BillingTerms{PeriodMonthly, PeriodAnnual, 1}
	if err := svc.Activate(context.Background(), 7, "pro", terms, "sub_1", 0); err != nil {
		t.Fatal(err)
	}
	c := lastCall(t, qs, qLcInsertActive)
	if c.args[iaBillingCycle] != "M" || c.args[iaTermType] != "A" {
		t.Fatalf("billing M / term A expected: %v", c.args)
	}
	if c.args[iaAmountMinor] != int64(100000) {
		t.Fatalf("per-unit amount snapshot 100000 expected, got %#v", c.args[iaAmountMinor])
	}
	if c.args[iaCost] != payment.MinorToMajor(8333, "USD") { // 100000/12 floored
		t.Fatalf("per-charge should be 83.33, got %#v", c.args[iaCost])
	}
	if c.args[iaRenewal] != time.Date(2027, 6, 8, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("term end should be +1 year, got %#v", c.args[iaRenewal])
	}
	if c.args[iaSeats] != nil {
		t.Fatalf("seats<=0 should bind nil, got %#v", c.args[iaSeats])
	}
}

func TestActivate_TrialAnchorsTermAtTrialEnd(t *testing.T) {
	svc, qs := newSvc(map[string][][]any{
		qLcPlanPolicy: {{"T", int64(30)}},
		qLcPlanPrice:  {{int64(100000), "USD"}},
	})
	svc.Now = fixedClock()
	if err := svc.Activate(context.Background(), 7, "pro", BillingTerms{PeriodMonthly, PeriodAnnual, 1}, "sub_1", 0); err != nil {
		t.Fatal(err)
	}
	c := lastCall(t, qs, qLcStartTrial)
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
	// rows: id, caption, currency, activation_mode, trial_days, billing_cycle, term_count, term_type, amount_minor, currency, provider_price_id
	svc, _ := newSvc(map[string][][]any{
		qBillGetAllPlans: {
			{"pro", "Pro", "USD", "A", int64(14), "M", int64(1), "M", int64(10000), "USD", "price_m"},
			{"pro", "Pro", "USD", "A", int64(14), "A", int64(1), "A", int64(100000), "USD", "price_a"},
			{"free", "Free", "USD", "F", nil, "", nil, nil, nil, nil, nil}, // LEFT JOIN, no price
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
	if pro.MonthlyCost != 100.0 || pro.AnnualCost != 1000.0 {
		t.Fatalf("derived headline costs wrong: monthly=%v annual=%v", pro.MonthlyCost, pro.AnnualCost)
	}
	if pro.Prices[1].AmountMinor != 100000 || pro.Prices[1].TermType != "A" {
		t.Fatalf("price rows wrong: %+v", pro.Prices)
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
