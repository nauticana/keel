package user

import (
	"errors"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
)

func TestResolveSubscriptionOffer(t *testing.T) {
	now := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	// qPlanPrices column order: billing_cycle, term_type, term_count, amount_minor, currency, provider_price_id
	rows := [][]any{
		{"M", "M", int64(1), int64(1000), "USD", "price_m"},  // $10/mo
		{"M", "A", int64(1), int64(10000), "USD", "price_a"}, // $100/yr billed monthly
		{"A", "A", int64(1), int64(10000), "USD", "price_y"}, // $100/yr billed once
	}

	t.Run("free when no price rows", func(t *testing.T) {
		off, err := resolveSubscriptionOffer(nil, &PartnerSetup{}, "P", now)
		if err != nil || off.paymentRequired || off.status != "A" || off.billingCycle != nil {
			t.Fatalf("want free offer, got %+v err %v", off, err)
		}
	})

	t.Run("cheapest when no terms requested", func(t *testing.T) {
		off, err := resolveSubscriptionOffer(rows, &PartnerSetup{}, "P", now)
		if err != nil {
			t.Fatal(err)
		}
		if !off.paymentRequired || off.amountMinor != int64(1000) || off.providerPriceID != "price_m" {
			t.Fatalf("want cheapest 1000, got %+v", off)
		}
		if off.installmentMinor != 1000 { // $10/mo, 1 installment
			t.Fatalf("installmentMinor = %v, want 1000", off.installmentMinor)
		}
	})

	t.Run("annual-billed-monthly installment + dates", func(t *testing.T) {
		off, err := resolveSubscriptionOffer(rows, &PartnerSetup{BillingCycle: "M", TermType: "A", TermCount: 1}, "P", now)
		if err != nil {
			t.Fatal(err)
		}
		if off.amountMinor != int64(10000) {
			t.Fatalf("amount_minor = %v, want 10000", off.amountMinor)
		}
		// $100.00/yr = 10000 cents ÷ 12 = 833 cents (floor) per installment
		if off.installmentMinor != 833 {
			t.Fatalf("installmentMinor = %v, want 833", off.installmentMinor)
		}
		if off.renewalDate != now.AddDate(1, 0, 0) {
			t.Fatalf("renewal = %v, want +1yr", off.renewalDate)
		}
		if off.nextChargeDate != now.AddDate(0, 1, 0) {
			t.Fatalf("next_charge = %v, want +1mo", off.nextChargeDate)
		}
	})

	t.Run("requested terms not offered is a bad request", func(t *testing.T) {
		_, err := resolveSubscriptionOffer(rows, &PartnerSetup{BillingCycle: "W", TermType: "W", TermCount: 1}, "P", now)
		var appErr *model.AppError
		if !errors.As(err, &appErr) || appErr.Status != 400 {
			t.Fatalf("err = %v, want 400", err)
		}
	})

	t.Run("negative price is rejected", func(t *testing.T) {
		bad := [][]any{{"M", "M", int64(1), int64(-1), "USD", "price_bad"}}
		if _, err := resolveSubscriptionOffer(bad, &PartnerSetup{}, "P", now); err == nil {
			t.Fatal("negative price accepted")
		}
	})

	// A priced offer follows the plan's activation mode as checkout does.
	for _, tc := range []struct {
		mode, status string
		payment      bool
	}{
		{"P", "P", true}, // pre-seeded row that checkout flips
		{"A", "", true},  // checkout inserts the row
		{"T", "", true},  // checkout starts the trial
		{"F", "A", false},
	} {
		off, err := resolveSubscriptionOffer(rows, &PartnerSetup{}, tc.mode, now)
		if err != nil || off.status != tc.status || off.paymentRequired != tc.payment {
			t.Errorf("mode %s: status %q payment %v err %v, want %q %v", tc.mode, off.status, off.paymentRequired, err, tc.status, tc.payment)
		}
	}
	if _, err := resolveSubscriptionOffer(nil, &PartnerSetup{}, "Z", now); err == nil {
		t.Error("an unknown activation mode must be refused")
	}
}
