package user

import (
	"testing"
	"time"
)

func TestResolveSubscriptionOffer(t *testing.T) {
	now := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	// qPlanPrices column order: billing_cycle, term_type, term_count, amount_minor, currency
	rows := [][]any{
		{"M", "M", int64(1), int64(1000), "USD"},  // $10/mo
		{"M", "A", int64(1), int64(10000), "USD"}, // $100/yr billed monthly
		{"A", "A", int64(1), int64(10000), "USD"}, // $100/yr billed once
	}

	t.Run("free when no price rows", func(t *testing.T) {
		off, err := resolveSubscriptionOffer(nil, &PartnerRegistration{}, "USD", now)
		if err != nil || off.paymentRequired || off.billingCycle != nil {
			t.Fatalf("want free offer, got %+v err %v", off, err)
		}
	})

	t.Run("cheapest when no terms requested", func(t *testing.T) {
		off, err := resolveSubscriptionOffer(rows, &PartnerRegistration{}, "USD", now)
		if err != nil {
			t.Fatal(err)
		}
		if !off.paymentRequired || off.amountMinor != int64(1000) {
			t.Fatalf("want cheapest 1000, got %+v", off)
		}
		if off.monthlyCost != 10.0 { // $10/mo, 1 installment
			t.Fatalf("monthlyCost = %v, want 10", off.monthlyCost)
		}
	})

	t.Run("annual-billed-monthly installment + dates", func(t *testing.T) {
		off, err := resolveSubscriptionOffer(rows, &PartnerRegistration{BillingCycle: "M", TermType: "A", TermCount: 1}, "USD", now)
		if err != nil {
			t.Fatal(err)
		}
		if off.amountMinor != int64(10000) {
			t.Fatalf("amount_minor = %v, want 10000", off.amountMinor)
		}
		// $100.00/yr = 10000 cents ÷ 12 = 833 cents (floor) = $8.33 per installment
		if off.monthlyCost != 8.33 {
			t.Fatalf("monthlyCost = %v, want 8.33", off.monthlyCost)
		}
		if off.renewalDate != now.AddDate(1, 0, 0) {
			t.Fatalf("renewal = %v, want +1yr", off.renewalDate)
		}
		if off.nextChargeDate != now.AddDate(0, 1, 0) {
			t.Fatalf("next_charge = %v, want +1mo", off.nextChargeDate)
		}
	})

	t.Run("requested terms not offered errors", func(t *testing.T) {
		_, err := resolveSubscriptionOffer(rows, &PartnerRegistration{BillingCycle: "W", TermType: "W", TermCount: 1}, "USD", now)
		if err == nil {
			t.Fatal("want error for unavailable terms")
		}
	})
}
