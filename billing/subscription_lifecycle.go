package billing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// SubscriptionLifecycle is the verb set over partner_plan_subscription.
// AbstractBillingService is the default impl (SQL is the overridable Queries
// map). Split from BillingService/ProviderBillingStore for interface segregation.
type SubscriptionLifecycle interface {
	// Activate opens a sub on the chosen terms, snapshotting the matching
	// subscription_plan_price (ErrPriceNotFound if none), in one transaction: it
	// flips the partner's pending row for the plan when there is one, else opens
	// a row per the plan's activation_mode, and closes the partner's free plan.
	// A live paid subscription is ErrSubscriptionActive unless it is this
	// provider subscription (a replay, which changes nothing). seats<=0 → NULL.
	Activate(ctx context.Context, partnerID int64, planID string, terms BillingTerms, providerSubID string, seats int64) error
	// ChangePlan atomically closes the current active/trial row and opens a fresh
	// one on terms; the target may be the current plan on other terms.
	ChangePlan(ctx context.Context, partnerID int64, newPlanID string, terms BillingTerms) error
	Reactivate(ctx context.Context, partnerID int64, planID string) error
	ConvertTrial(ctx context.Context, partnerID int64, providerSubID string) error
	SetSeats(ctx context.Context, partnerID int64, planID string, seats int64) error
	// CancelByPartner cancels immediately (C) or at period end (effective_cancel_date).
	// An immediate cancel starts the successor or fallback plan.
	CancelByPartner(ctx context.Context, partnerID int64, mode CancelMode) error
	// CancelByProviderSubID is the webhook path; returns rows affected (0 → no local row).
	CancelByProviderSubID(ctx context.Context, providerSubID string, mode CancelMode) (int, error)
	// CheckChange lists the live-counted resources the partner holds beyond
	// planID's limits (nil without Quotas). ChangePlan to a paid plan refuses
	// them with ErrOverTargetLimit; a move to a free plan is never refused.
	CheckChange(ctx context.Context, partnerID int64, planID string) ([]port.QuotaOverage, error)
	// ScheduleChange ends the current subscription at period end and records the
	// free plan that starts then (ErrNotFreePlan otherwise).
	ScheduleChange(ctx context.Context, partnerID int64, planID string) error
	// ResumeRenewal undoes a period-end cancellation or scheduled change.
	ResumeRenewal(ctx context.Context, partnerID int64) error
	// EndDue ends up to limit subscriptions the provider does not hold whose
	// effective_cancel_date or endda has passed, starting each one's successor or
	// fallback plan. It continues past a row whose next plan cannot start and
	// returns how many it ended with those failures joined.
	EndDue(ctx context.Context, limit int) (int, error)
	// SetDunningState moves the CHAR(1) status (e.g. "X" past-due, "A" active).
	SetDunningState(ctx context.Context, partnerID int64, providerSubID, status string) error
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
	qLcPartnerRows            = "lc_partner_rows"
	qLcStartTrial             = "lc_start_trial"
	qLcConvertTrial           = "lc_convert_trial"
	qLcChangePlanCurrent      = "lc_change_plan_current"
	qLcChangePlanClose        = "lc_change_plan_close"
	qLcReactivate             = "lc_reactivate"
	qLcSetSeats               = "lc_set_seats"
	qLcCancelPartnerPeriodEnd = "lc_cancel_partner_period_end"
	qLcCancelSubIDPeriodEnd   = "lc_cancel_subid_period_end"
	qLcSetDunning             = "lc_set_dunning"
	qLcScheduleChange         = "lc_schedule_change"
	qLcResumeRenewal          = "lc_resume_renewal"
	qLcLiveByPartner          = "lc_live_by_partner"
	qLcLiveByProviderSub      = "lc_live_by_provider_sub"
	qLcDueToEnd               = "lc_due_to_end"
	qLcEndRow                 = "lc_end_row"
	qLcInsertFree             = "lc_insert_free"
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
  (partner_id, plan_id, begda, installment_minor, currency, status, billing_cycle,
   term_count, term_type, amount_minor, renewal_date, next_charge_date, provider_subscription_id, seats)
VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 'A', ?, ?, ?, ?, ?, ?, ?, ?)`,

	qLcFlipPending: `
UPDATE partner_plan_subscription
   SET status = 'A', provider_subscription_id = ?, seats = ?, begda = CURRENT_TIMESTAMP,
       installment_minor = ?, currency = ?, billing_cycle = ?, term_count = ?, term_type = ?,
       amount_minor = ?, renewal_date = ?, next_charge_date = ?
 WHERE partner_id = ? AND plan_id = ? AND status = 'P'
 RETURNING partner_id`,

	// Activate's view of the partner: live and pending rows with their plan's mode.
	qLcPartnerRows: `
SELECT ps.plan_id, ps.begda, ps.status, COALESCE(ps.provider_subscription_id, ''), sp.activation_mode
  FROM partner_plan_subscription ps
  JOIN subscription_plan sp ON sp.id = ps.plan_id
 WHERE ps.partner_id = ? AND ps.status IN ('A', 'T', 'X', 'P')
   AND (ps.endda IS NULL OR ps.endda > CURRENT_TIMESTAMP)`,

	// Trial dates are anchored at trial_end (the paid term starts then).
	qLcStartTrial: `
INSERT INTO partner_plan_subscription
  (partner_id, plan_id, begda, installment_minor, currency, status, billing_cycle,
   term_count, term_type, amount_minor, trial_end, renewal_date, next_charge_date, provider_subscription_id, seats)
VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 'T', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,

	// A paid invoice activates a trialing sub and clears the past-due state
	// SetDunningState set on a failed one.
	qLcConvertTrial: `
UPDATE partner_plan_subscription
   SET status = 'A', trial_end = NULL
 WHERE partner_id = ? AND provider_subscription_id = ? AND status IN ('T', 'X')`,

	// Lock and read the current row before closing it. Keeping this separate
	// from UPDATE makes the transaction portable to databases without RETURNING.
	qLcChangePlanCurrent: `
SELECT COALESCE(provider_subscription_id, ''), plan_id
  FROM partner_plan_subscription
 WHERE partner_id = ? AND status IN ('A', 'T', 'X')
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)
 ORDER BY begda DESC
 LIMIT 1
 FOR UPDATE`,

	// change-plan step 2: close the current active/trial/past-due row.
	qLcChangePlanClose: `
UPDATE partner_plan_subscription
   SET status = 'C', endda = CURRENT_TIMESTAMP, cancelled_at = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND status IN ('A', 'T', 'X')
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)`,

	qLcReactivate: `
UPDATE partner_plan_subscription
   SET status = 'A', auto_renew = TRUE, cancelled_at = NULL,
       effective_cancel_date = NULL, successor_plan_id = NULL, endda = NULL
 WHERE partner_id = ? AND plan_id = ? AND status IN ('A', 'C', 'P')`,

	qLcSetSeats: `
UPDATE partner_plan_subscription
   SET seats = ?
 WHERE partner_id = ? AND plan_id = ? AND status IN ('A', 'T')`,

	qLcCancelPartnerPeriodEnd: `
UPDATE partner_plan_subscription
   SET effective_cancel_date = COALESCE(renewal_date, trial_end), auto_renew = FALSE,
       successor_plan_id = NULL
 WHERE partner_id = ? AND status IN ('A', 'T', 'X')
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)`,

	// RETURNING so len(Rows) is the affected count (mysql override: ROW_COUNT()).
	qLcCancelSubIDPeriodEnd: `
UPDATE partner_plan_subscription
   SET effective_cancel_date = COALESCE(renewal_date, trial_end), auto_renew = FALSE
 WHERE provider_subscription_id = ? AND status IN ('A', 'T', 'X')
 RETURNING partner_id`,

	qLcScheduleChange: `
UPDATE partner_plan_subscription
   SET effective_cancel_date = COALESCE(renewal_date, trial_end), auto_renew = FALSE,
       successor_plan_id = ?
 WHERE partner_id = ? AND status IN ('A', 'T', 'X')
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)
 RETURNING partner_id`,

	qLcResumeRenewal: `
UPDATE partner_plan_subscription
   SET auto_renew = TRUE, effective_cancel_date = NULL, successor_plan_id = NULL
 WHERE partner_id = ? AND status IN ('A', 'T', 'X')
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)`,

	qLcLiveByPartner: `
SELECT ` + endingColumns + `
  FROM partner_plan_subscription ps
  JOIN subscription_plan sp ON sp.id = ps.plan_id
 WHERE ps.partner_id = ? AND ps.status IN ('A', 'T', 'X')
   AND (ps.endda IS NULL OR ps.endda > CURRENT_TIMESTAMP)`,

	qLcLiveByProviderSub: `
SELECT ` + endingColumns + `
  FROM partner_plan_subscription ps
  JOIN subscription_plan sp ON sp.id = ps.plan_id
 WHERE ps.provider_subscription_id = ? AND ps.status IN ('A', 'T', 'X')`,

	// Provider-held rows end on the provider's cancellation event, not here.
	qLcDueToEnd: `
SELECT ` + endingColumns + `
  FROM partner_plan_subscription ps
  JOIN subscription_plan sp ON sp.id = ps.plan_id
 WHERE ps.status IN ('A', 'T', 'X')
   AND COALESCE(ps.provider_subscription_id, '') = ''
   AND (ps.effective_cancel_date <= CURRENT_TIMESTAMP OR ps.endda <= CURRENT_TIMESTAMP)
 ORDER BY ps.partner_id, ps.begda
 LIMIT ?`,

	// The status guard makes a concurrent or repeated end a no-op (no rows returned).
	qLcEndRow: `
UPDATE partner_plan_subscription
   SET status = 'C', auto_renew = FALSE,
       cancelled_at = COALESCE(cancelled_at, CURRENT_TIMESTAMP),
       endda = LEAST(COALESCE(endda, CURRENT_TIMESTAMP), COALESCE(effective_cancel_date, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP)
 WHERE partner_id = ? AND plan_id = ? AND begda = ? AND status IN ('A', 'T', 'X')
 RETURNING partner_id`,

	// A free row carries no charge terms, as at registration. The NOT EXISTS is
	// an approximate guard: it skips the insert while the partner holds another
	// live or pending row but does not serialize concurrent ends of two rows.
	qLcInsertFree: `
INSERT INTO partner_plan_subscription
  (partner_id, plan_id, begda, installment_minor, currency, status, auto_renew)
SELECT ?, sp.id, CURRENT_TIMESTAMP, 0, sp.currency, 'A', TRUE
  FROM subscription_plan sp
 WHERE sp.id = ?
   AND NOT EXISTS (SELECT 1 FROM partner_plan_subscription ps
                    WHERE ps.partner_id = ? AND ps.status IN ('A', 'T', 'X', 'P')
                      AND (ps.endda IS NULL OR ps.endda > CURRENT_TIMESTAMP))
 RETURNING plan_id`,

	qLcSetDunning: `
UPDATE partner_plan_subscription
   SET status = ?
 WHERE partner_id = ? AND provider_subscription_id = ? AND status IN ('A', 'T', 'P', 'X')`,
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
	amountUnitMinor  int64 // price for one term_type unit (snapshot)
	installmentMinor int64 // one installment
	currency         string
	termCount        int64
	termType         string
	billingCycle     string
	renewalDate      time.Time // term end
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
	total, err := terms.ContractTotalMinor(amountUnit)
	if err != nil {
		return planCharge{}, err
	}
	return planCharge{
		amountUnitMinor:  amountUnit,
		installmentMinor: InstallmentMinor(total, n, 0),
		currency:         currency,
		termCount:        int64(terms.TermCount),
		termType:         terms.TermType.Code(),
		billingCycle:     terms.BillingCycle.Code(),
		renewalDate:      terms.TermEnd(start),
	}, nil
}

func (s *AbstractBillingService) Activate(ctx context.Context, partnerID int64, planID string, terms BillingTerms, providerSubID string, seats int64) error {
	s.init(ctx)
	pol, err := s.loadPlanPolicy(ctx, planID)
	if err != nil {
		return err
	}
	switch pol.mode {
	case ActivateCreateActive, ActivatePending, ActivateTrial, ActivateFree:
	default:
		return fmt.Errorf("unknown activation_mode %q for plan %s", pol.mode, planID)
	}
	now := s.now()
	pc, err := s.loadPlanCharge(ctx, planID, terms, now)
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
	rows, err := tx.Query(ctx, qLcPartnerRows, partnerID)
	if err != nil {
		return err
	}
	pending := false
	var free []endingRow
	for _, row := range rows.Rows {
		r := activationRow{
			planID:        common.AsString(row[0]),
			begda:         common.AsTime(row[1]),
			status:        common.AsString(row[2]),
			providerSubID: common.AsString(row[3]),
			mode:          ActivationMode(common.AsString(row[4])),
		}
		switch {
		case r.status == "P":
			pending = pending || r.planID == planID
		case r.mode == ActivateFree:
			free = append(free, endingRow{partnerID: partnerID, planID: r.planID, begda: r.begda})
		case providerSubID != "" && r.providerSubID == providerSubID:
			s.quotasChanged(ctx, partnerID) // a replay may follow a lost invalidation
			return nil
		default:
			return fmt.Errorf("%w: partner %d holds plan %s", ErrSubscriptionActive, partnerID, r.planID)
		}
	}
	for _, r := range free {
		if _, err := tx.Query(ctx, qLcEndRow, r.partnerID, r.planID, r.begda); err != nil {
			return err
		}
	}
	nextCharge := now // first installment due at start
	switch {
	case pending:
		res, err := tx.Query(ctx, qLcFlipPending,
			providerSubID, seatsArg(seats), pc.installmentMinor, pc.currency, pc.billingCycle,
			pc.termCount, pc.termType, pc.amountUnitMinor, pc.renewalDate, nextCharge, partnerID, planID)
		if err != nil {
			return err
		}
		if len(res.Rows) == 0 {
			return fmt.Errorf("billing: pending %s row for partner %d changed during activation", planID, partnerID)
		}
	case pol.mode == ActivateTrial:
		trialEnd := now.AddDate(0, 0, int(pol.trialDays))
		termEnd := terms.normalized().TermEnd(trialEnd) // paid term starts at trial end
		if _, err := tx.Query(ctx, qLcStartTrial,
			partnerID, planID, pc.installmentMinor, pc.currency, pc.billingCycle,
			pc.termCount, pc.termType, pc.amountUnitMinor, trialEnd, termEnd, trialEnd, providerSubID, seatsArg(seats)); err != nil {
			return err
		}
	default:
		if _, err := tx.Query(ctx, qLcInsertActive,
			partnerID, planID, pc.installmentMinor, pc.currency, pc.billingCycle,
			pc.termCount, pc.termType, pc.amountUnitMinor, pc.renewalDate, nextCharge, providerSubID, seatsArg(seats)); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	s.quotasChanged(ctx, partnerID)
	return nil
}

// activationRow is one qLcPartnerRows row.
type activationRow struct {
	planID        string
	begda         time.Time
	status        string
	providerSubID string
	mode          ActivationMode
}

func (s *AbstractBillingService) ChangePlan(ctx context.Context, partnerID int64, newPlanID string, terms BillingTerms) error {
	s.init(ctx)
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
	if err := s.ChangePlanTx(ctx, tx, partnerID, newPlanID, terms); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	s.quotasChanged(ctx, partnerID)
	return nil
}

// ChangePlanTx is ChangePlan on a caller-owned transaction, so an app can
// commit its own writes atomically with the plan change. The caller owns
// commit/rollback, must build the tx with a query map that includes
// TxQueries() entries, and calls Quotas.InvalidatePartner after its commit.
func (s *AbstractBillingService) ChangePlanTx(ctx context.Context, tx port.TxQueryService, partnerID int64, newPlanID string, terms BillingTerms) error {
	s.init(ctx)
	pol, err := s.loadPlanPolicy(ctx, newPlanID)
	if err != nil {
		return err
	}
	current, err := tx.Query(ctx, qLcChangePlanCurrent, partnerID)
	if err != nil {
		return err
	}
	providerSubID, currentPlanID := "", ""
	if len(current.Rows) > 0 {
		providerSubID = common.AsString(current.Rows[0][0])
		currentPlanID = common.AsString(current.Rows[0][1])
	}
	if pol.mode == ActivateFree {
		// The provider must cancel its subscription first (ProviderSubscriptionService
		// schedules the change); closing the row here would leave it billing.
		if providerSubID != "" {
			return ErrProviderSubscription
		}
		if _, err := tx.Query(ctx, qLcChangePlanClose, partnerID); err != nil {
			return err
		}
		started, err := startFree(ctx, tx, partnerID, newPlanID)
		if err != nil {
			return err
		}
		if !started {
			return ErrSubscriptionPending
		}
		return nil
	}
	// A new cycle of the current plan keeps its limits.
	if newPlanID != currentPlanID {
		if err := s.refuseOverages(ctx, partnerID, newPlanID); err != nil {
			return err
		}
	}
	now := s.now()
	pc, err := s.loadPlanCharge(ctx, newPlanID, terms, now)
	if err != nil {
		return err
	}
	if _, err := tx.Query(ctx, qLcChangePlanClose, partnerID); err != nil {
		return err
	}
	_, err = tx.Query(ctx, qLcInsertActive,
		partnerID, newPlanID, pc.installmentMinor, pc.currency, pc.billingCycle,
		pc.termCount, pc.termType, pc.amountUnitMinor, pc.renewalDate, now, providerSubID, nil)
	return err
}

// TxQueries returns the merged billing query map for callers that BeginTx
// themselves and run ChangePlanTx inside it.
func (s *AbstractBillingService) TxQueries(ctx context.Context) map[string]string {
	s.init(ctx)
	return s.allQueries
}

func (s *AbstractBillingService) Reactivate(ctx context.Context, partnerID int64, planID string) error {
	s.init(ctx)
	if _, err := s.qs.Query(ctx, qLcReactivate, partnerID, planID); err != nil {
		return err
	}
	s.quotasChanged(ctx, partnerID)
	return nil
}

func (s *AbstractBillingService) ConvertTrial(ctx context.Context, partnerID int64, providerSubID string) error {
	s.init(ctx)
	if _, err := s.qs.Query(ctx, qLcConvertTrial, partnerID, providerSubID); err != nil {
		return err
	}
	s.quotasChanged(ctx, partnerID)
	return nil
}

func (s *AbstractBillingService) SetSeats(ctx context.Context, partnerID int64, planID string, seats int64) error {
	s.init(ctx)
	_, err := s.qs.Query(ctx, qLcSetSeats, seatsArg(seats), partnerID, planID)
	return err
}

func (s *AbstractBillingService) CancelByPartner(ctx context.Context, partnerID int64, mode CancelMode) error {
	s.init(ctx)
	if mode == CancelAtPeriodEnd {
		_, err := s.qs.Query(ctx, qLcCancelPartnerPeriodEnd, partnerID)
		return err
	}
	_, err := s.endLive(ctx, qLcLiveByPartner, partnerID)
	return err
}

func (s *AbstractBillingService) CancelByProviderSubID(ctx context.Context, providerSubID string, mode CancelMode) (int, error) {
	s.init(ctx)
	if mode == CancelAtPeriodEnd {
		res, err := s.qs.Query(ctx, qLcCancelSubIDPeriodEnd, providerSubID)
		if err != nil {
			return 0, err
		}
		return len(res.Rows), nil
	}
	return s.endLive(ctx, qLcLiveByProviderSub, providerSubID)
}

func (s *AbstractBillingService) ScheduleChange(ctx context.Context, partnerID int64, planID string) error {
	s.init(ctx)
	pol, err := s.loadPlanPolicy(ctx, planID)
	if err != nil {
		return err
	}
	if pol.mode != ActivateFree {
		return fmt.Errorf("%w: %s", ErrNotFreePlan, planID)
	}
	res, err := s.qs.Query(ctx, qLcScheduleChange, planID, partnerID)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return ErrNoSubscription
	}
	return nil
}

func (s *AbstractBillingService) CheckChange(ctx context.Context, partnerID int64, planID string) ([]port.QuotaOverage, error) {
	s.init(ctx)
	pol, err := s.loadPlanPolicy(ctx, planID)
	if err != nil {
		return nil, err
	}
	if pol.mode == ActivateFree || s.Quotas == nil {
		return nil, nil
	}
	return s.Quotas.PlanOverages(ctx, partnerID, planID)
}

// refuseOverages is the downgrade guard: a paid target must hold everything
// the partner already has. A free target and the fallback are never refused,
// so a cancellation always goes through.
func (s *AbstractBillingService) refuseOverages(ctx context.Context, partnerID int64, planID string) error {
	if s.Quotas == nil {
		return nil
	}
	overages, err := s.Quotas.PlanOverages(ctx, partnerID, planID)
	if err != nil {
		return err
	}
	if len(overages) > 0 {
		return &OverTargetLimitError{PlanID: planID, Overages: overages}
	}
	return nil
}

func (s *AbstractBillingService) ResumeRenewal(ctx context.Context, partnerID int64) error {
	s.init(ctx)
	_, err := s.qs.Query(ctx, qLcResumeRenewal, partnerID)
	return err
}

// EndDue ends each row in its own transaction so one failure cannot hold the
// others back.
func (s *AbstractBillingService) EndDue(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("billing: EndDue limit must be positive, got %d", limit)
	}
	s.init(ctx)
	res, err := s.qs.Query(ctx, qLcDueToEnd, limit)
	if err != nil {
		return 0, err
	}
	ended := 0
	cache := planModes{}
	var errs []error
	for _, row := range res.Rows {
		if err := ctx.Err(); err != nil {
			return ended, errors.Join(append(errs, err)...)
		}
		n, err := s.endRows(ctx, cache, []endingRow{parseEndingRow(row)})
		ended += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return ended, errors.Join(errs...)
}

func (s *AbstractBillingService) SetDunningState(ctx context.Context, partnerID int64, providerSubID, status string) error {
	s.init(ctx)
	if _, err := s.qs.Query(ctx, qLcSetDunning, status, partnerID, providerSubID); err != nil {
		return err
	}
	s.quotasChanged(ctx, partnerID)
	return nil
}

var _ SubscriptionLifecycle = (*AbstractBillingService)(nil)
