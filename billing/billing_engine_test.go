package billing

import (
	"context"
	"testing"
	"time"

	"github.com/nauticana/keel/payment"
)

func newEngine(qs *fakeQS) *SelfScheduledEngine {
	e := &SelfScheduledEngine{Repo: fakeRepo{qs: qs}}
	e.init(context.Background())
	return e
}

func TestAdvanceSubscription_WithinTerm(t *testing.T) {
	qs := &fakeQS{}
	e := newEngine(qs)
	begda := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	renewal := begda.AddDate(1, 0, 0)    // annual term
	nextCharge := begda.AddDate(0, 3, 0) // month 3 of 12, not last
	terms := BillingTerms{PeriodMonthly, PeriodAnnual, 1}

	e.advanceSubscription(context.Background(), 7, "pro", begda, terms, "USD", 12, renewal, nextCharge, false, true)

	c := lastCall(t, qs, qSSAdvanceCharge)
	// args: next_charge_date, partner, plan, begda
	if c.args[0] != nextCharge.AddDate(0, 1, 0) {
		t.Fatalf("next_charge should advance one month, got %#v", c.args[0])
	}
	if c.args[1] != int64(7) || c.args[2] != "pro" || c.args[3] != begda {
		t.Fatalf("key args wrong: %v", c.args)
	}
}

// At renewal the price refreshes to the current offer.
func TestAdvanceSubscription_TermEndAutoRenewRefreshesPrice(t *testing.T) {
	qs := &fakeQS{rows: map[string][][]any{
		qSSPlanPrice: {{int64(110000)}}, // price rose to $1100/yr for the new term
	}}
	e := newEngine(qs)
	begda := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	renewal := begda.AddDate(1, 0, 0)
	terms := BillingTerms{PeriodMonthly, PeriodAnnual, 1}

	e.advanceSubscription(context.Background(), 7, "pro", begda, terms, "USD", 12, renewal, renewal.AddDate(0, -1, 0), true, true)

	c := lastCall(t, qs, qSSRenewTerm)
	// args: new renewal, new next_charge, amount_minor, monthly_cost, partner, plan, begda
	if c.args[0] != renewal.AddDate(1, 0, 0) {
		t.Fatalf("renewal should move +1 year, got %#v", c.args[0])
	}
	if c.args[1] != renewal { // new term's first charge = old term end
		t.Fatalf("next_charge should be old term end, got %#v", c.args[1])
	}
	if c.args[2] != int64(110000) { // refreshed per-unit amount
		t.Fatalf("amount_minor should refresh to 110000, got %#v", c.args[2])
	}
	if c.args[3] != payment.MinorToMajor(110000/12, "USD") {
		t.Fatalf("monthly_cost should be the new per-installment, got %#v", c.args[3])
	}
}

// If the offer was withdrawn, the term can't renew — it ends.
func TestAdvanceSubscription_RenewOfferWithdrawnEnds(t *testing.T) {
	qs := &fakeQS{} // qSSPlanPrice returns no rows
	e := newEngine(qs)
	begda := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	renewal := begda.AddDate(1, 0, 0)
	terms := BillingTerms{PeriodMonthly, PeriodAnnual, 1}

	e.advanceSubscription(context.Background(), 7, "pro", begda, terms, "USD", 12, renewal, renewal.AddDate(0, -1, 0), true, true)

	c := lastCall(t, qs, qSSEndTerm)
	if c.args[0] != renewal {
		t.Fatalf("endda should be term end, got %#v", c.args[0])
	}
}

func TestAdvanceSubscription_TermEndNoRenew(t *testing.T) {
	qs := &fakeQS{}
	e := newEngine(qs)
	begda := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	renewal := begda.AddDate(1, 0, 0)
	terms := BillingTerms{PeriodMonthly, PeriodAnnual, 1}

	e.advanceSubscription(context.Background(), 7, "pro", begda, terms, "USD", 12, renewal, renewal.AddDate(0, -1, 0), true, false)

	c := lastCall(t, qs, qSSEndTerm)
	if c.args[0] != renewal { // endda = term end
		t.Fatalf("endda should be term end, got %#v", c.args[0])
	}
}
