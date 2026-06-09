package billing

import (
	"fmt"
	"strings"
	"time"
)

// BillingPeriod is a PERIOD_TYPE code used on the three axes of BillingTerms.
// An empty/unknown code resolves to monthly.
type BillingPeriod string

const (
	PeriodDaily     BillingPeriod = "D"
	PeriodWeekly    BillingPeriod = "W"
	PeriodMonthly   BillingPeriod = "M"
	PeriodQuarterly BillingPeriod = "Q"
	PeriodAnnual    BillingPeriod = "A"
)

// ParseBillingPeriod defaults to monthly for an empty/unrecognized code.
func ParseBillingPeriod(code string) BillingPeriod {
	switch BillingPeriod(strings.ToUpper(strings.TrimSpace(code))) {
	case PeriodDaily:
		return PeriodDaily
	case PeriodWeekly:
		return PeriodWeekly
	case PeriodQuarterly:
		return PeriodQuarterly
	case PeriodAnnual:
		return PeriodAnnual
	default:
		return PeriodMonthly
	}
}

func (p BillingPeriod) Code() string {
	if p == "" {
		return string(PeriodMonthly)
	}
	return string(p)
}

// AddUnits advances t by n periods via AddDate (calendar-aware month/leap math).
func (p BillingPeriod) AddUnits(t time.Time, n int) time.Time {
	switch p {
	case PeriodDaily:
		return t.AddDate(0, 0, n)
	case PeriodWeekly:
		return t.AddDate(0, 0, 7*n)
	case PeriodQuarterly:
		return t.AddDate(0, 3*n, 0)
	case PeriodAnnual:
		return t.AddDate(n, 0, 0)
	default:
		return t.AddDate(0, n, 0)
	}
}

func (p BillingPeriod) NextRenewal(t time.Time) time.Time { return p.AddUnits(t, 1) }

// A period is measured in months (M/Q/A) or days (W/D), never mixed.
func (p BillingPeriod) months() (int, bool) {
	switch p {
	case PeriodMonthly:
		return 1, true
	case PeriodQuarterly:
		return 3, true
	case PeriodAnnual:
		return 12, true
	default:
		return 0, false
	}
}

func (p BillingPeriod) days() (int, bool) {
	switch p {
	case PeriodDaily:
		return 1, true
	case PeriodWeekly:
		return 7, true
	default:
		return 0, false
	}
}

// InstallmentsPerUnit counts billing_cycle charges in one term_type unit — e.g.
// (A,M)→12, (Q,M)→3. Errors when the cycle doesn't evenly divide the unit (or
// crosses the month/day measure) rather than returning a wrong count.
func InstallmentsPerUnit(termType, billingCycle BillingPeriod) (int, error) {
	if tm, ok := termType.months(); ok {
		if bm, ok2 := billingCycle.months(); ok2 && bm > 0 && tm%bm == 0 {
			return tm / bm, nil
		}
	}
	if td, ok := termType.days(); ok {
		if bd, ok2 := billingCycle.days(); ok2 && bd > 0 && td%bd == 0 {
			return td / bd, nil
		}
	}
	return 0, fmt.Errorf("billing cycle %q does not evenly divide term unit %q", billingCycle.Code(), termType.Code())
}

// BillingTerms selects a price offer: how often charged, the commitment length,
// and the unit the price is quoted in. Zero value is monthly / 1-month term.
type BillingTerms struct {
	BillingCycle BillingPeriod // how often charged
	TermType     BillingPeriod // commitment/pricing unit; amount is per one of these
	TermCount    int           // number of term_type units committed (default 1)
}

func (t BillingTerms) normalized() BillingTerms {
	if t.BillingCycle == "" {
		t.BillingCycle = PeriodMonthly
	}
	if t.TermType == "" {
		t.TermType = PeriodMonthly
	}
	if t.TermCount < 1 {
		t.TermCount = 1
	}
	return t
}

// TotalInstallments is the number of charges over the whole term.
func (t BillingTerms) TotalInstallments() (int, error) {
	t = t.normalized()
	per, err := InstallmentsPerUnit(t.TermType, t.BillingCycle)
	if err != nil {
		return 0, err
	}
	return per * t.TermCount, nil
}

// TermEnd is the renewal_date: begda + term_count term_type units.
func (t BillingTerms) TermEnd(begda time.Time) time.Time {
	t = t.normalized()
	return t.TermType.AddUnits(begda, t.TermCount)
}

// ContractTotalMinor is the full committed value: per-unit amount × term_count.
func (t BillingTerms) ContractTotalMinor(amountPerUnitMinor int64) int64 {
	return amountPerUnitMinor * int64(t.normalized().TermCount)
}

// InstallmentMinor is the charge for installment k (0-based) of n. Every charge
// is floor(total/n) except the last, which absorbs the remainder so they sum to
// exactly totalMinor.
func InstallmentMinor(totalMinor int64, n, k int) int64 {
	if n <= 1 {
		return totalMinor
	}
	base := totalMinor / int64(n)
	if k >= n-1 {
		return totalMinor - base*int64(n-1)
	}
	return base
}
