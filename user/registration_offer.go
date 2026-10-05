package user

import (
	"fmt"
	"time"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

// subscriptionOffer is the resolved price and schedule snapshot for the
// subscription a registration creates. The NULLable fields are nil for a free
// offer.
type subscriptionOffer struct {
	paymentRequired bool
	status          string // row status; "" when checkout creates the row
	providerPriceID string
	monthlyCost     string // per-installment display, exact major-unit decimal
	currency        string // offer currency ("" for free → caller keeps plan currency)
	billingCycle    any
	termType        any
	termCount       any
	amountMinor     any
	renewalDate     any
	nextChargeDate  any
}

var freeOffer = subscriptionOffer{status: "A", monthlyCost: "0"}

// resolveSubscriptionOffer picks the offer from a plan's subscription_plan_price
// rows: the requested terms, else the cheapest; no rows or a zero price is
// free. A priced offer follows the plan's activation mode as
// billing.SubscriptionLifecycle.Activate does at checkout: a pending plan gets
// a 'P' row that checkout activates, a create-active or trial plan gets its row
// from checkout, and a free-mode plan is active at once. The first installment
// is collected at checkout, so next_charge_date is the second.
func resolveSubscriptionOffer(rows [][]any, setup *PartnerSetup, mode string, now time.Time) (subscriptionOffer, error) {
	switch billing.ActivationMode(mode) {
	case billing.ActivateCreateActive, billing.ActivatePending, billing.ActivateTrial, billing.ActivateFree:
	default:
		return subscriptionOffer{}, fmt.Errorf("unknown activation_mode %q", mode)
	}
	if len(rows) == 0 {
		return freeOffer, nil
	}
	idx := -1
	if setup.BillingCycle != "" || setup.TermType != "" || setup.TermCount > 0 {
		wc := billing.ParseBillingPeriod(setup.BillingCycle).Code()
		wt := billing.ParseBillingPeriod(setup.TermType).Code()
		wn := max(setup.TermCount, 1)
		for i, row := range rows {
			if common.AsString(row[0]) == wc && common.AsString(row[1]) == wt && int(common.AsInt32(row[2])) == wn {
				idx = i
				break
			}
		}
		if idx < 0 {
			return subscriptionOffer{}, model.NewBadRequest(fmt.Sprintf("plan does not offer the selected terms (%s/%d%s)", wc, wn, wt))
		}
	} else {
		for i := range rows {
			if idx < 0 || common.AsInt64(rows[i][3]) < common.AsInt64(rows[idx][3]) {
				idx = i
			}
		}
	}

	row := rows[idx]
	amount := common.AsInt64(row[3])
	if amount <= 0 {
		return freeOffer, nil
	}
	terms := billing.BillingTerms{
		BillingCycle: billing.ParseBillingPeriod(common.AsString(row[0])),
		TermType:     billing.ParseBillingPeriod(common.AsString(row[1])),
		TermCount:    int(common.AsInt32(row[2])),
	}
	n, err := terms.TotalInstallments()
	if err != nil {
		return subscriptionOffer{}, err
	}
	monthlyCost, ok := common.FormatMinorUnits(billing.InstallmentMinor(terms.ContractTotalMinor(amount), n, 0), common.AsString(row[4]))
	if !ok {
		return subscriptionOffer{}, fmt.Errorf("plan price has unknown currency %q", common.AsString(row[4]))
	}
	offer := subscriptionOffer{
		providerPriceID: common.AsString(row[5]),
		monthlyCost:     monthlyCost,
		currency:        common.AsString(row[4]),
		billingCycle:    terms.BillingCycle.Code(),
		termType:        terms.TermType.Code(),
		termCount:       max(terms.TermCount, 1),
		amountMinor:     amount,
		renewalDate:     terms.TermEnd(now),
		nextChargeDate:  terms.BillingCycle.NextRenewal(now),
	}
	switch billing.ActivationMode(mode) {
	case billing.ActivateFree:
		offer.status = "A"
	case billing.ActivatePending:
		offer.status, offer.paymentRequired = "P", true
	default:
		offer.paymentRequired = true
	}
	return offer, nil
}

// planChoice is a resolved plan and offer.
type planChoice struct {
	id, currency string
	offer        subscriptionOffer
}
