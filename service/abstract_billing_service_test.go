package service

import (
	"context"
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
	// args: id, partner, provider, token, partner, provider
	if c.args[1] != int64(7) || c.args[2] != "stripe" || c.args[3] != "cus_9" || c.args[4] != int64(7) || c.args[5] != "stripe" {
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
