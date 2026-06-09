package billing

import (
	"context"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/payment"
)

// SubscriptionLifecycle is the verb set over partner_plan_subscription.
// AbstractBillingService is the default impl (SQL is the overridable Queries
// map). Split from BillingService/ProviderBillingStore for interface segregation.
type SubscriptionLifecycle interface {
	// Activate opens a sub on the chosen terms per the plan's activation_mode,
	// snapshotting the matching subscription_plan_price (ErrPriceNotFound if none),
	// setting renewal_date = term end and next_charge_date. seats<=0 → NULL.
	Activate(ctx context.Context, partnerID int64, planID string, terms BillingTerms, providerSubID string, seats int64) error
	// ChangePlan atomically closes the current active/trial row and opens a fresh one.
	ChangePlan(ctx context.Context, partnerID int64, newPlanID string, terms BillingTerms) error
	Reactivate(ctx context.Context, partnerID int64, planID string) error
	ConvertTrial(ctx context.Context, partnerID int64) error
	SetSeats(ctx context.Context, partnerID int64, planID string, seats int64) error
	// CancelByPartner cancels immediately (C) or at period end (effective_cancel_date).
	CancelByPartner(ctx context.Context, partnerID int64, mode CancelMode) error
	// CancelByProviderSubID is the webhook path; returns rows affected (0 → no local row).
	CancelByProviderSubID(ctx context.Context, providerSubID string, mode CancelMode) (int, error)
	// SetDunningState moves the CHAR(1) status (e.g. "X" past-due, "A" active).
	SetDunningState(ctx context.Context, partnerID int64, status string) error
}

// ActivationMode is subscription_plan.activation_mode (SUBSCRIPTION_ACTIVATION_MODE
// dict). Open dictionary — add new policies as rows + a switch case.
type ActivationMode string

const (
	ActivateCreateActive ActivationMode = "A" // INSERT a fresh active row (provider already created the sub)
	ActivatePending      ActivationMode = "P" // flip a pre-seeded status='P' row to 'A'
	ActivateTrial        ActivationMode = "T" // start status='T' + trial_end; convert on first paid invoice
	ActivateFree         ActivationMode = "F" // free plan: active immediately, no provider sub / charge
)

// CancelMode selects immediate vs at-period-end cancellation (routes the UPDATE).
type CancelMode string

const (
	CancelImmediate   CancelMode = "immediate"
	CancelAtPeriodEnd CancelMode = "at_period_end"
)

const (
	qLcPlanPolicy             = "lc_plan_policy"
	qLcPlanPrice              = "lc_plan_price"
	qLcInsertActive           = "lc_insert_active"
	qLcFlipPending            = "lc_flip_pending"
	qLcStartTrial             = "lc_start_trial"
	qLcConvertTrial           = "lc_convert_trial"
	qLcChangePlanClose        = "lc_change_plan_close"
	qLcReactivate             = "lc_reactivate"
	qLcSetSeats               = "lc_set_seats"
	qLcCancelPartnerPeriodEnd = "lc_cancel_partner_period_end"
	qLcCancelSubIDImmediate   = "lc_cancel_subid_immediate"
	qLcCancelSubIDPeriodEnd   = "lc_cancel_subid_period_end"
	qLcSetDunning             = "lc_set_dunning"
)

// lifecycleQueries is pgsql; a mysql consumer overrides the RETURNING entries via
// Queries (mysql uses ROW_COUNT()). Dates/amounts are computed in Go and bound,
// so the inserts carry no dialect-specific INTERVAL math.
var lifecycleQueries = map[string]string{
	qLcPlanPolicy: `
SELECT activation_mode, COALESCE(trial_days, 14)
  FROM subscription_plan WHERE id = ? AND is_active = TRUE`,

	qLcPlanPrice: `
SELECT amount_minor, currency
  FROM subscription_plan_price
 WHERE plan_id = ? AND billing_cycle = ? AND term_type = ? AND term_count = ?`,

	// Fresh active row (create-active / free / change-plan target).
	qLcInsertActive: `
INSERT INTO partner_plan_subscription
  (partner_id, plan_id, begda, monthly_cost, currency, status, billing_cycle,
   term_count, term_type, amount_minor, renewal_date, next_charge_date, provider_subscription_id, seats)
VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 'A', ?, ?, ?, ?, ?, ?, ?, ?)`,

	qLcFlipPending: `
UPDATE partner_plan_subscription
   SET status = 'A', provider_subscription_id = ?, seats = ?, begda = CURRENT_TIMESTAMP,
       monthly_cost = ?, currency = ?, billing_cycle = ?, term_count = ?, term_type = ?,
       amount_minor = ?, renewal_date = ?, next_charge_date = ?
 WHERE partner_id = ? AND plan_id = ? AND status = 'P'`,

	// Trial: dates anchored at trial_end (paid term starts then), so ConvertTrial
	// only flips T→A.
	qLcStartTrial: `
INSERT INTO partner_plan_subscription
  (partner_id, plan_id, begda, monthly_cost, currency, status, billing_cycle,
   term_count, term_type, amount_minor, trial_end, renewal_date, next_charge_date, provider_subscription_id, seats)
VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 'T', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,

	qLcConvertTrial: `
UPDATE partner_plan_subscription
   SET status = 'A', trial_end = NULL
 WHERE partner_id = ? AND status = 'T'`,

	// change-plan step 1: close the current active/trial row.
	qLcChangePlanClose: `
UPDATE partner_plan_subscription
   SET status = 'C', endda = CURRENT_TIMESTAMP, cancelled_at = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND status IN ('A', 'T')
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)`,

	qLcReactivate: `
UPDATE partner_plan_subscription
   SET status = 'A', auto_renew = TRUE, cancelled_at = NULL,
       effective_cancel_date = NULL, endda = NULL
 WHERE partner_id = ? AND plan_id = ? AND status IN ('A', 'C', 'P')`,

	qLcSetSeats: `
UPDATE partner_plan_subscription
   SET seats = ?
 WHERE partner_id = ? AND plan_id = ? AND status IN ('A', 'T')`,

	qLcCancelPartnerPeriodEnd: `
UPDATE partner_plan_subscription
   SET effective_cancel_date = COALESCE(renewal_date, trial_end), auto_renew = FALSE
 WHERE partner_id = ? AND status IN ('A', 'T')
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)`,

	// RETURNING so len(Rows) is the affected count (mysql override: ROW_COUNT()).
	qLcCancelSubIDImmediate: `
UPDATE partner_plan_subscription
   SET status = 'C', cancelled_at = CURRENT_TIMESTAMP, auto_renew = FALSE
 WHERE provider_subscription_id = ? AND status IN ('A', 'T')
 RETURNING partner_id`,

	qLcCancelSubIDPeriodEnd: `
UPDATE partner_plan_subscription
   SET effective_cancel_date = COALESCE(renewal_date, trial_end), auto_renew = FALSE
 WHERE provider_subscription_id = ? AND status IN ('A', 'T')
 RETURNING partner_id`,

	qLcSetDunning: `
UPDATE partner_plan_subscription
   SET status = ?
 WHERE partner_id = ? AND status IN ('A', 'T', 'P', 'X')`,
}

// seatsArg binds seats<=0 as NULL.
func seatsArg(seats int64) any {
	if seats > 0 {
		return seats
	}
	return nil
}

type planPolicy struct {
	mode      ActivationMode
	trialDays int64
}

// loadPlanPolicy returns ErrPlanNotFound when the plan is missing or inactive.
func (s *AbstractBillingService) loadPlanPolicy(ctx context.Context, planID string) (planPolicy, error) {
	res, err := s.qs.Query(ctx, qLcPlanPolicy, planID)
	if err != nil {
		return planPolicy{}, err
	}
	if len(res.Rows) == 0 {
		return planPolicy{}, fmt.Errorf("%w: %s", ErrPlanNotFound, planID)
	}
	row := res.Rows[0]
	return planPolicy{
		mode:      ActivationMode(common.AsString(row[0])),
		trialDays: common.AsInt64(row[1]),
	}, nil
}

// planCharge is the priced+scheduled result of a (plan, terms) selection.
type planCharge struct {
	amountUnitMinor int64   // price for one term_type unit (snapshot)
	perChargeMajor  float64 // one installment, major units (display monthly_cost)
	currency        string
	termCount       int64
	termType        string
	billingCycle    string
	renewalDate     time.Time // term end
}

// loadPlanCharge reads the price row for the chosen terms and derives the
// installment + term end. ErrPriceNotFound if the offer doesn't exist.
func (s *AbstractBillingService) loadPlanCharge(ctx context.Context, planID string, terms BillingTerms, start time.Time) (planCharge, error) {
	terms = terms.normalized()
	res, err := s.qs.Query(ctx, qLcPlanPrice, planID, terms.BillingCycle.Code(), terms.TermType.Code(), terms.TermCount)
	if err != nil {
		return planCharge{}, err
	}
	if len(res.Rows) == 0 {
		return planCharge{}, fmt.Errorf("%w: plan %s %s/%d%s", ErrPriceNotFound, planID, terms.BillingCycle.Code(), terms.TermCount, terms.TermType.Code())
	}
	n, err := terms.TotalInstallments()
	if err != nil {
		return planCharge{}, err
	}
	row := res.Rows[0]
	amountUnit := common.AsInt64(row[0])
	currency := common.AsString(row[1])
	total := terms.ContractTotalMinor(amountUnit)
	return planCharge{
		amountUnitMinor: amountUnit,
		perChargeMajor:  payment.MinorToMajor(InstallmentMinor(total, n, 0), currency),
		currency:        currency,
		termCount:       int64(terms.TermCount),
		termType:        terms.TermType.Code(),
		billingCycle:    terms.BillingCycle.Code(),
		renewalDate:     terms.TermEnd(start),
	}, nil
}

func (s *AbstractBillingService) Activate(ctx context.Context, partnerID int64, planID string, terms BillingTerms, providerSubID string, seats int64) error {
	s.init(ctx)
	pol, err := s.loadPlanPolicy(ctx, planID)
	if err != nil {
		return err
	}
	now := s.now()
	pc, err := s.loadPlanCharge(ctx, planID, terms, now)
	if err != nil {
		return err
	}
	nextCharge := now // first installment due at start
	switch pol.mode {
	case ActivateCreateActive, ActivateFree:
		_, err = s.qs.Query(ctx, qLcInsertActive,
			partnerID, planID, pc.perChargeMajor, pc.currency, pc.billingCycle,
			pc.termCount, pc.termType, pc.amountUnitMinor, pc.renewalDate, nextCharge, providerSubID, seatsArg(seats))
	case ActivatePending:
		_, err = s.qs.Query(ctx, qLcFlipPending,
			providerSubID, seatsArg(seats), pc.perChargeMajor, pc.currency, pc.billingCycle,
			pc.termCount, pc.termType, pc.amountUnitMinor, pc.renewalDate, nextCharge, partnerID, planID)
	case ActivateTrial:
		trialEnd := now.AddDate(0, 0, int(pol.trialDays))
		termEnd := terms.normalized().TermEnd(trialEnd) // paid term starts at trial end
		_, err = s.qs.Query(ctx, qLcStartTrial,
			partnerID, planID, pc.perChargeMajor, pc.currency, pc.billingCycle,
			pc.termCount, pc.termType, pc.amountUnitMinor, trialEnd, termEnd, trialEnd, providerSubID, seatsArg(seats))
	default:
		return fmt.Errorf("unknown activation_mode %q for plan %s", pol.mode, planID)
	}
	return err
}

func (s *AbstractBillingService) ChangePlan(ctx context.Context, partnerID int64, newPlanID string, terms BillingTerms) error {
	s.init(ctx)
	now := s.now()
	pc, err := s.loadPlanCharge(ctx, newPlanID, terms, now)
	if err != nil {
		return err
	}
	tx, err := s.Repo.BeginTx(ctx, s.allQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Query(ctx, qLcChangePlanClose, partnerID); err != nil {
		return err
	}
	if _, err := tx.Query(ctx, qLcInsertActive,
		partnerID, newPlanID, pc.perChargeMajor, pc.currency, pc.billingCycle,
		pc.termCount, pc.termType, pc.amountUnitMinor, pc.renewalDate, now, "", nil); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *AbstractBillingService) Reactivate(ctx context.Context, partnerID int64, planID string) error {
	s.init(ctx)
	_, err := s.qs.Query(ctx, qLcReactivate, partnerID, planID)
	return err
}

func (s *AbstractBillingService) ConvertTrial(ctx context.Context, partnerID int64) error {
	s.init(ctx)
	_, err := s.qs.Query(ctx, qLcConvertTrial, partnerID)
	return err
}

func (s *AbstractBillingService) SetSeats(ctx context.Context, partnerID int64, planID string, seats int64) error {
	s.init(ctx)
	_, err := s.qs.Query(ctx, qLcSetSeats, seatsArg(seats), partnerID, planID)
	return err
}

func (s *AbstractBillingService) CancelByPartner(ctx context.Context, partnerID int64, mode CancelMode) error {
	s.init(ctx)
	q := qBillCancelSub // immediate
	if mode == CancelAtPeriodEnd {
		q = qLcCancelPartnerPeriodEnd
	}
	_, err := s.qs.Query(ctx, q, partnerID)
	return err
}

func (s *AbstractBillingService) CancelByProviderSubID(ctx context.Context, providerSubID string, mode CancelMode) (int, error) {
	s.init(ctx)
	q := qLcCancelSubIDImmediate
	if mode == CancelAtPeriodEnd {
		q = qLcCancelSubIDPeriodEnd
	}
	res, err := s.qs.Query(ctx, q, providerSubID)
	if err != nil {
		return 0, err
	}
	return len(res.Rows), nil
}

func (s *AbstractBillingService) SetDunningState(ctx context.Context, partnerID int64, status string) error {
	s.init(ctx)
	_, err := s.qs.Query(ctx, qLcSetDunning, status, partnerID)
	return err
}

var _ SubscriptionLifecycle = (*AbstractBillingService)(nil)
