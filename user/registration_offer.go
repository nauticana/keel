package user

import (
	"fmt"
	"time"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

// subscriptionOffer is the resolved price and schedule snapshot for the
// subscription a registration creates. The NULLable fields are nil when unset.
type subscriptionOffer struct {
	paymentRequired  bool
	status           string // row status; "" when checkout creates the row
	providerPriceID  string
	installmentMinor int64
	currency         string // offer currency ("" for free → caller keeps plan currency)
	billingCycle     any
	termType         any
	termCount        any
	amountMinor      any
	renewalDate      any
	nextChargeDate   any
	trialEnd         any
}

// freeOffer is active at once, except on a trial plan, where it is a trial
// without a card that EndDue ends at trial_end.
func freeOffer(mode billing.ActivationMode, trialDays int, now time.Time) subscriptionOffer {
	if mode == billing.ActivateTrial {
		return subscriptionOffer{status: "T", trialEnd: now.AddDate(0, 0, trialDays)}
	}
	return subscriptionOffer{status: "A"}
}

// resolveSubscriptionOffer picks the offer from a plan's subscription_plan_price
// rows: the requested terms, else the cheapest; no rows or a zero price is
// freeOffer. A priced offer follows the plan's activation mode as
// billing.SubscriptionLifecycle.Activate does at checkout: a pending plan gets
// a 'P' row that checkout activates, a create-active or trial plan gets its row
// from checkout, and a free-mode plan is active at once. The first installment
// is collected at checkout, so next_charge_date is the second.
func resolveSubscriptionOffer(rows [][]any, setup *PartnerSetup, mode billing.ActivationMode, trialDays int, now time.Time) (subscriptionOffer, error) {
	switch mode {
	case billing.ActivateCreateActive, billing.ActivatePending, billing.ActivateTrial, billing.ActivateFree:
	default:
		return subscriptionOffer{}, fmt.Errorf("unknown activation_mode %q", mode)
	}
	if len(rows) == 0 {
		return freeOffer(mode, trialDays, now), nil
	}
	idx := -1
	if setup.BillingCycle != "" || setup.TermType != "" || setup.TermCount > 0 {
		wc := billing.ParseBillingPeriod(setup.BillingCycle).Code()
		wt := billing.ParseBillingPeriod(setup.TermType).Code()
		wn := max(setup.TermCount, 1)
		for i, row := range rows {
			if common.AsString(row[0]) == wc && common.AsString(row[1]) == wt && common.AsInt32(row[2]) == wn {
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
	if amount < 0 {
		return subscriptionOffer{}, fmt.Errorf("plan price cannot be negative")
	}
	if amount == 0 {
		return freeOffer(mode, trialDays, now), nil
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
	total, err := terms.ContractTotalMinor(amount)
	if err != nil {
		return subscriptionOffer{}, err
	}
	offer := subscriptionOffer{
		providerPriceID:  common.AsString(row[5]),
		installmentMinor: billing.InstallmentMinor(total, n, 0),
		currency:         common.AsString(row[4]),
		billingCycle:     terms.BillingCycle.Code(),
		termType:         terms.TermType.Code(),
		termCount:        max(terms.TermCount, 1),
		amountMinor:      amount,
		renewalDate:      terms.TermEnd(now),
		nextChargeDate:   terms.BillingCycle.NextRenewal(now),
	}
	switch mode {
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
