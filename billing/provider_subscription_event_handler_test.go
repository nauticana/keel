package billing

import (
	"context"
	"testing"

	"github.com/nauticana/keel/payment"
)

func TestProviderSubscriptionEventHandlerScopesInvoiceTransitions(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		eventKind  string
		queryName  string
		wantArgs   []any
		invoiceID  string
		minorUnits int64
	}{
		{
			name:       "paid",
			eventKind:  payment.KindInvoicePaid,
			queryName:  qLcConvertTrial,
			wantArgs:   []any{int64(42), "sub_current"},
			invoiceID:  "in_paid",
			minorUnits: 1999,
		},
		{
			name:      "failed",
			eventKind: payment.KindInvoicePaymentFailed,
			queryName: qLcSetDunning,
			wantArgs:  []any{"X", int64(42), "sub_current"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, qs := newSvc(nil)
			handler := NewProviderSubscriptionEventHandler(svc, svc, SubscriptionHandlerOptions{})
			err := handler.OnPaymentEvent(ctx, &payment.PaymentEvent{
				EventKind:      tc.eventKind,
				InvoiceID:      tc.invoiceID,
				SubscriptionID: "sub_current",
				MinorUnits:     tc.minorUnits,
				Currency:       "USD",
				Metadata:       map[string]string{"partner_id": "42"},
			})
			if err != nil {
				t.Fatal(err)
			}
			call := lastCall(t, qs, tc.queryName)
			if len(call.args) != len(tc.wantArgs) {
				t.Fatalf("%s args = %v, want %v", tc.queryName, call.args, tc.wantArgs)
			}
			for i := range tc.wantArgs {
				if call.args[i] != tc.wantArgs[i] {
					t.Fatalf("%s args = %v, want %v", tc.queryName, call.args, tc.wantArgs)
				}
			}
		})
	}
}

// termsFrom is the seam that lets a fixed-interval product (e.g. annual-only)
// resolve the right offer without threading term metadata through every
// checkout, while staying backward compatible: a zero DefaultTerms must keep
// the historical monthly/1-unit default.
func TestSubscriptionHandlerOptions_termsFrom(t *testing.T) {
	keys := SubscriptionHandlerOptions{
		BillingCycleKey: "billing_cycle",
		TermTypeKey:     "term_type",
		TermCountKey:    "term_count",
	}
	annual := keys
	annual.DefaultTerms = BillingTerms{BillingCycle: PeriodAnnual, TermType: PeriodAnnual, TermCount: 1}

	cases := []struct {
		name string
		opts SubscriptionHandlerOptions
		meta map[string]string
		want BillingTerms
	}{
		{
			// Backward compat: zero DefaultTerms + no metadata → empty terms, which
			// Activate's normalized() turns into monthly/1 (today's behavior).
			name: "zero default, no metadata",
			opts: keys,
			meta: map[string]string{},
			want: BillingTerms{},
		},
		{
			name: "annual default, no metadata",
			opts: annual,
			meta: map[string]string{},
			want: BillingTerms{BillingCycle: PeriodAnnual, TermType: PeriodAnnual, TermCount: 1},
		},
		{
			name: "metadata overrides default per field",
			opts: annual,
			meta: map[string]string{"billing_cycle": "M", "term_type": "M", "term_count": "3"},
			want: BillingTerms{BillingCycle: PeriodMonthly, TermType: PeriodMonthly, TermCount: 3},
		},
		{
			name: "partial metadata keeps default for absent fields",
			opts: annual,
			meta: map[string]string{"term_count": "2"},
			want: BillingTerms{BillingCycle: PeriodAnnual, TermType: PeriodAnnual, TermCount: 2},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.opts.termsFrom(c.meta); got != c.want {
				t.Fatalf("termsFrom = %+v, want %+v", got, c.want)
			}
		})
	}

	// The zero-default empty terms must normalize to the historical default.
	if n := (BillingTerms{}).normalized(); n.BillingCycle != PeriodMonthly || n.TermType != PeriodMonthly || n.TermCount != 1 {
		t.Fatalf("zero terms normalized = %+v, want monthly/monthly/1", n)
	}
}
