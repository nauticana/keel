package billing

import (
	"testing"
	"time"
)

func TestInstallmentsPerUnit(t *testing.T) {
	cases := []struct {
		term, billing BillingPeriod
		want          int
		wantErr       bool
	}{
		{PeriodMonthly, PeriodMonthly, 1, false},
		{PeriodAnnual, PeriodAnnual, 1, false},
		{PeriodAnnual, PeriodMonthly, 12, false},
		{PeriodAnnual, PeriodQuarterly, 4, false},
		{PeriodQuarterly, PeriodMonthly, 3, false},
		{PeriodWeekly, PeriodDaily, 7, false},
		{PeriodWeekly, PeriodWeekly, 1, false},
		{PeriodAnnual, PeriodWeekly, 0, true},     // month vs day measure
		{PeriodMonthly, PeriodQuarterly, 0, true}, // billing > term
		{PeriodMonthly, PeriodWeekly, 0, true},    // month vs day
	}
	for _, c := range cases {
		got, err := InstallmentsPerUnit(c.term, c.billing)
		if c.wantErr {
			if err == nil {
				t.Errorf("InstallmentsPerUnit(%s,%s) expected error", c.term, c.billing)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("InstallmentsPerUnit(%s,%s) = %d,%v want %d", c.term, c.billing, got, err, c.want)
		}
	}
}

// The four cases the user enumerated, end to end.
func TestBillingTerms_UserCases(t *testing.T) {
	begda := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		terms       BillingTerms
		perUnit     int64 // amount_minor per term_type unit
		wantN       int
		wantTotal   int64
		wantTermEnd time.Time
		wantFirst   int64 // installment 0 charge
	}{
		{"$100/mo monthly", BillingTerms{PeriodMonthly, PeriodMonthly, 1}, 10000, 1, 10000, begda.AddDate(0, 1, 0), 10000},
		{"$1000/yr monthly", BillingTerms{PeriodMonthly, PeriodAnnual, 1}, 100000, 12, 100000, begda.AddDate(1, 0, 0), 8333},
		{"$1000/yr at once", BillingTerms{PeriodAnnual, PeriodAnnual, 1}, 100000, 1, 100000, begda.AddDate(1, 0, 0), 100000},
		{"3yr fixed annual, monthly", BillingTerms{PeriodMonthly, PeriodAnnual, 3}, 100000, 36, 300000, begda.AddDate(3, 0, 0), 8333},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := c.terms.TotalInstallments()
			if err != nil || n != c.wantN {
				t.Fatalf("TotalInstallments = %d,%v want %d", n, err, c.wantN)
			}
			total := c.terms.ContractTotalMinor(c.perUnit)
			if total != c.wantTotal {
				t.Fatalf("ContractTotalMinor = %d want %d", total, c.wantTotal)
			}
			if end := c.terms.TermEnd(begda); !end.Equal(c.wantTermEnd) {
				t.Fatalf("TermEnd = %v want %v", end, c.wantTermEnd)
			}
			if first := InstallmentMinor(total, n, 0); first != c.wantFirst {
				t.Fatalf("first installment = %d want %d", first, c.wantFirst)
			}
			// Exactness: installments must sum to the contract total.
			var sum int64
			for k := 0; k < n; k++ {
				sum += InstallmentMinor(total, n, k)
			}
			if sum != c.wantTotal {
				t.Fatalf("installments sum = %d want %d", sum, c.wantTotal)
			}
		})
	}
}

func TestInstallmentMinor_RemainderOnLast(t *testing.T) {
	// 100000 / 12 = 8333 r4 → 11×8333 + 1×8337 = 100000
	total, n := int64(100000), 12
	for k := 0; k < n-1; k++ {
		if got := InstallmentMinor(total, n, k); got != 8333 {
			t.Fatalf("installment %d = %d want 8333", k, got)
		}
	}
	if last := InstallmentMinor(total, n, n-1); last != 8337 {
		t.Fatalf("last installment = %d want 8337", last)
	}
}
