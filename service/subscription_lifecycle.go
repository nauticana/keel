package service

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/common"
)

// SubscriptionLifecycle is the verb set over the basis partner_plan_subscription
// table that every SaaS re-implements: activate a sub (per the plan's configured
// activation mode), change plan, cancel (immediately or at period end, by partner
// or by provider subscription id), convert a trial, adjust seats, and move the
// dunning state. AbstractBillingService is the default impl; the SQL is the
// overridable Queries map (same idiom as BillingService).
//
// Kept separate from BillingService (read/write CRUD) and ProviderBillingStore
// (webhook writes) — interface segregation: a consumer that only reads billing
// state isn't forced to implement the lifecycle verbs.
type SubscriptionLifecycle interface {
	// Activate makes the partner's subscription to planID active, honoring the
	// plan's activation_mode: create-active / activate-pending (flip a P row) /
	// trial (status T + trial_end) / free. providerSubID is the provider
	// subscription id (empty for free / self-scheduled); seats<=0 stores NULL.
	Activate(ctx context.Context, partnerID int64, planID, providerSubID string, seats int64) error
	// ChangePlan moves the partner to newPlanID, closing the current active/trial
	// row and opening a fresh active one — atomically, history preserved.
	ChangePlan(ctx context.Context, partnerID int64, newPlanID string) error
	// Reactivate un-cancels a cancelled / scheduled-to-cancel row (resume / win-back).
	Reactivate(ctx context.Context, partnerID int64, planID string) error
	// ConvertTrial flips a trialing row to active (first paid invoice).
	ConvertTrial(ctx context.Context, partnerID int64) error
	// SetSeats sets the seat quantity on the partner's active/trial sub to plan.
	SetSeats(ctx context.Context, partnerID int64, planID string, seats int64) error
	// CancelByPartner cancels the partner's active sub immediately (status C) or
	// at period end (sets effective_cancel_date for the reconcile backstop).
	CancelByPartner(ctx context.Context, partnerID int64, mode CancelMode) error
	// CancelByProviderSubID cancels the sub matching a provider subscription id
	// (the webhook path); returns the number of rows affected (0 → no local row).
	CancelByProviderSubID(ctx context.Context, providerSubID string, mode CancelMode) (int, error)
	// SetDunningState moves the dunning status (e.g. "X" past-due/expired on a
	// failed invoice, "A" back to active once it clears). CHAR(1) status code.
	SetDunningState(ctx context.Context, partnerID int64, status string) error
}

// ActivationMode is the per-plan checkout-activation policy stored in
// subscription_plan.activation_mode (CHAR(1), SUBSCRIPTION_ACTIVATION_MODE dict).
// The four core policies; the dictionary is open, so one-time / invoice-terms /
// manual-approval can be added later as rows + a switch case, no schema break.
type ActivationMode string

const (
	ActivateCreateActive ActivationMode = "A" // INSERT a fresh active row (provider already created the sub)
	ActivatePending      ActivationMode = "P" // flip a pre-seeded status='P' row to 'A'
	ActivateTrial        ActivationMode = "T" // start status='T' + trial_end; convert on first paid invoice
	ActivateFree         ActivationMode = "F" // free plan: active immediately, no provider sub / charge
)

// CancelMode selects immediate vs at-period-end cancellation. Not persisted —
// it routes to a different UPDATE.
type CancelMode string

const (
	CancelImmediate   CancelMode = "immediate"
	CancelAtPeriodEnd CancelMode = "at_period_end"
)

const (
	qLcPlanPolicy             = "lc_plan_policy"
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

// lifecycleQueries is pgsql-flavored (the default dialect); a mysql consumer
// overrides the affected entries via AbstractBillingService.Queries — notably the
// INTERVAL math and the RETURNING clauses (mysql lacks RETURNING; use ROW_COUNT()).
var lifecycleQueries = map[string]string{
	qLcPlanPolicy: `
SELECT activation_mode, COALESCE(trial_days, 14), monthly_cost, currency
  FROM subscription_plan WHERE id = ? AND is_active = TRUE`,

	// create-active / free / change-plan target: a fresh active row.
	qLcInsertActive: `
INSERT INTO partner_plan_subscription
  (partner_id, plan_id, begda, monthly_cost, currency, status, billing_cycle, renewal_date, provider_subscription_id, seats)
SELECT ?, ?, CURRENT_TIMESTAMP, monthly_cost, currency, 'A', 'M',
       CURRENT_TIMESTAMP + INTERVAL '1 month', ?, ?
  FROM subscription_plan WHERE id = ?`,

	qLcFlipPending: `
UPDATE partner_plan_subscription
   SET status = 'A', provider_subscription_id = ?, seats = ?,
       begda = CURRENT_TIMESTAMP, renewal_date = CURRENT_TIMESTAMP + INTERVAL '1 month'
 WHERE partner_id = ? AND plan_id = ? AND status = 'P'`,

	qLcStartTrial: `
INSERT INTO partner_plan_subscription
  (partner_id, plan_id, begda, monthly_cost, currency, status, billing_cycle, trial_end, provider_subscription_id, seats)
SELECT ?, ?, CURRENT_TIMESTAMP, monthly_cost, currency, 'T', 'M',
       CURRENT_TIMESTAMP + (? * INTERVAL '1 day'), ?, ?
  FROM subscription_plan WHERE id = ?`,

	qLcConvertTrial: `
UPDATE partner_plan_subscription
   SET status = 'A', trial_end = NULL
 WHERE partner_id = ? AND status = 'T'`,

	// change-plan step 1: close the current active/trial row (history preserved).
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

	// RETURNING so len(Rows) is the affected count (the webhook path needs to
	// know whether a local row matched). mysql override: drop RETURNING, read ROW_COUNT().
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

// seatsArg maps a seat count to a NULLable bind: <=0 → NULL (non-seat plans),
// >0 → the count.
func seatsArg(seats int64) any {
	if seats > 0 {
		return seats
	}
	return nil
}

func (s *AbstractBillingService) Activate(ctx context.Context, partnerID int64, planID, providerSubID string, seats int64) error {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qLcPlanPolicy, planID)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("%w: %s", ErrPlanNotFound, planID)
	}
	mode := ActivationMode(common.AsString(res.Rows[0][0]))
	trialDays := common.AsInt64(res.Rows[0][1])
	switch mode {
	case ActivateCreateActive, ActivateFree:
		_, err = s.qs.Query(ctx, qLcInsertActive, partnerID, planID, providerSubID, seatsArg(seats), planID)
	case ActivatePending:
		_, err = s.qs.Query(ctx, qLcFlipPending, providerSubID, seatsArg(seats), partnerID, planID)
	case ActivateTrial:
		_, err = s.qs.Query(ctx, qLcStartTrial, partnerID, planID, trialDays, providerSubID, seatsArg(seats), planID)
	default:
		return fmt.Errorf("unknown activation_mode %q for plan %s", mode, planID)
	}
	return err
}

func (s *AbstractBillingService) ChangePlan(ctx context.Context, partnerID int64, newPlanID string) error {
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
	if _, err := tx.Query(ctx, qLcChangePlanClose, partnerID); err != nil {
		return err
	}
	if _, err := tx.Query(ctx, qLcInsertActive, partnerID, newPlanID, "", nil, newPlanID); err != nil {
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
	q := qBillCancelSub // immediate (reuses the existing partner-wide cancel)
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
