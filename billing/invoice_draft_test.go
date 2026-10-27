package billing

import (
	"context"
	"errors"
	"math"
	"testing"
)

func TestInvoiceDraftTotalMinor(t *testing.T) {
	total, err := (&InvoiceDraft{Lines: []InvoiceLineDraft{{Quantity: 3, UnitPriceMinor: 250}, {Quantity: 1, UnitPriceMinor: -100}}}).TotalMinor()
	if err != nil || total != 650 {
		t.Fatalf("total = %d, %v", total, err)
	}
	for name, lines := range map[string][]InvoiceLineDraft{
		"line":         {{Quantity: 2, UnitPriceMinor: math.MaxInt64/2 + 1}},
		"negated min":  {{Quantity: -1, UnitPriceMinor: math.MinInt64}},
		"sum":          {{Quantity: 1, UnitPriceMinor: math.MaxInt64}, {Quantity: 1, UnitPriceMinor: 1}},
		"negative sum": {{Quantity: 1, UnitPriceMinor: math.MinInt64}, {Quantity: 1, UnitPriceMinor: -1}},
	} {
		if _, err := (&InvoiceDraft{Lines: lines}).TotalMinor(); !errors.Is(err, ErrInvoiceAmountOverflow) {
			t.Errorf("%s: %v, want ErrInvoiceAmountOverflow", name, err)
		}
	}
}

func TestCreateInvoiceRefusesOverflowBeforeWriting(t *testing.T) {
	tx := &fakeTx{}
	e := &SelfScheduledEngine{Repo: fakeRepo{qs: &fakeQS{}, tx: tx}}
	draft := &InvoiceDraft{Currency: "usd", Lines: []InvoiceLineDraft{{Quantity: 2, UnitPriceMinor: math.MaxInt64}}}
	if _, _, err := e.createInvoice(context.Background(), 7, draft); !errors.Is(err, ErrInvoiceAmountOverflow) || tx.begun != 0 {
		t.Fatalf("err = %v, transactions begun = %d", err, tx.begun)
	}
}
