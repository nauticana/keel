package billing

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

const (
	qSSCreateInvoice = "ss_create_invoice"
	qSSInsertLine    = "ss_insert_line"
	qSSMarkPaid      = "ss_mark_paid"
	qSSMarkAction    = "ss_mark_action_required"
	qSSMarkRetry     = "ss_mark_retry"
	qSSListRetryable = "ss_list_retryable"
	qSSListDueSubs   = "ss_list_due_subs"
	qSSAdvanceCharge = "ss_advance_charge"
	qSSPlanPrice     = "ss_plan_price"
	qSSRenewTerm     = "ss_renew_term"
	qSSEndTerm       = "ss_end_term"
)

var selfSchedQueries = map[string]string{
	qSSCreateInvoice: `
INSERT INTO invoice (id, partner_id, invoice_number, status, subtotal, tax, total, total_minor, currency, issued_at)
VALUES (?, ?, ?, 'O', ?, 0, ?, ?, ?, CURRENT_TIMESTAMP)`,

	qSSInsertLine: `
INSERT INTO invoice_line (invoice_id, seq, description, quantity, unit_price, amount)
VALUES (?, ?, ?, ?, ?, ?)`,

	qSSMarkPaid: `UPDATE invoice SET status = 'P', paid_at = CURRENT_TIMESTAMP, provider_charge_id = ? WHERE id = ?`,

	qSSMarkAction: `UPDATE invoice SET status = 'A', provider_charge_id = ?, last_error = NULL WHERE id = ?`,

	qSSMarkRetry: `
UPDATE invoice
   SET attempt_count = attempt_count + 1, last_error = ?,
       next_attempt_at = CURRENT_TIMESTAMP + INTERVAL '1 day'
 WHERE id = ?`,

	// Attempted-but-open invoices due for a dunning retry.
	qSSListRetryable: `
SELECT id, partner_id, total_minor, currency, attempt_count
  FROM invoice
 WHERE status = 'O' AND attempt_count > 0
   AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP)
 ORDER BY id`,

	// Active subs with an installment due now.
	qSSListDueSubs: `
SELECT partner_id, plan_id, begda, currency, billing_cycle, term_count, term_type,
       amount_minor, renewal_date, next_charge_date, auto_renew
  FROM partner_plan_subscription
 WHERE status = 'A' AND next_charge_date IS NOT NULL AND next_charge_date <= CURRENT_TIMESTAMP
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)
 ORDER BY partner_id, plan_id, begda`,

	qSSAdvanceCharge: `
UPDATE partner_plan_subscription SET next_charge_date = ?
 WHERE partner_id = ? AND plan_id = ? AND begda = ?`,

	// Current price for the offer, re-read at renewal (price locks only per term).
	qSSPlanPrice: `
SELECT amount_minor
  FROM subscription_plan_price
 WHERE plan_id = ? AND billing_cycle = ? AND term_type = ? AND term_count = ?`,

	// Roll into the next term, re-snapshotting the refreshed price.
	qSSRenewTerm: `
UPDATE partner_plan_subscription SET renewal_date = ?, next_charge_date = ?, amount_minor = ?, monthly_cost = ?
 WHERE partner_id = ? AND plan_id = ? AND begda = ?`,

	// Term complete, not renewing: stop charging, end the row.
	qSSEndTerm: `
UPDATE partner_plan_subscription SET next_charge_date = NULL, endda = ?, auto_renew = FALSE
 WHERE partner_id = ? AND plan_id = ? AND begda = ?`,
}

// SelfScheduledEngine runs the billing cycle itself: build a period invoice,
// charge it off-session, handle the outcome (paid / SCA / dunning). Inert until
// its closures are wired. Test in provider test mode before enabling.
type SelfScheduledEngine struct {
	Repo        port.DatabaseRepository
	Charge      payment.ChargeClient
	Journal     logger.ApplicationLogger
	MaxAttempts int // suspend after this many failed attempts (default 3)

	// BillSubscriptionsFromTable enables the built-in installment pass: charge
	// every due partner_plan_subscription from its snapshot terms, advance, and
	// renew/end at term boundary. Alternative to the DuePartners/BuildInvoice
	// closures. Off by default.
	BillSubscriptionsFromTable bool

	// DuePartners / BuildInvoice drive the closure-based pass (project owns the
	// invoice). BuildInvoice returns (nil,nil) to skip a partner.
	DuePartners  func(ctx context.Context) ([]int64, error)
	BuildInvoice func(ctx context.Context, partnerID int64) (*InvoiceDraft, error)
	// Credentials resolves the partner's vaulted customer + payment-method tokens.
	Credentials func(ctx context.Context, partnerID int64) (customer, paymentMethod string, err error)
	// AdvanceRenewal advances renewal_date after a charge (closure model only).
	AdvanceRenewal func(ctx context.Context, partnerID int64) error
	// Suspend marks the partner past-due after dunning exhaustion.
	Suspend func(ctx context.Context, partnerID int64) error
	// OnRequiresAction fires when a charge needs SCA (res carries client_secret / action URL).
	OnRequiresAction func(ctx context.Context, partnerID, invoiceID int64, res payment.ChargeResult)
	OnPaid           func(ctx context.Context, partnerID, invoiceID int64)
	OnFailed         func(ctx context.Context, partnerID, invoiceID int64, res payment.ChargeResult)

	initOnce sync.Once
	qs       port.QueryService
}

func (e *SelfScheduledEngine) init(ctx context.Context) {
	e.initOnce.Do(func() {
		e.qs = e.Repo.GetQueryService(ctx, selfSchedQueries)
		if e.MaxAttempts <= 0 {
			e.MaxAttempts = 3
		}
	})
}

func (e *SelfScheduledEngine) EnsureSubscription(ctx context.Context, partnerID int64, planID string) error {
	return nil // the project creates the local subscription row in its own flow
}

func (e *SelfScheduledEngine) HandleEvent(ctx context.Context, ev *payment.PaymentEvent) error {
	return nil // self-scheduled does not depend on provider webhooks
}

// RunCycle runs one pass: retry open invoices, then bill due subs/partners.
func (e *SelfScheduledEngine) RunCycle(ctx context.Context) error {
	if e.Charge == nil || e.Credentials == nil {
		return nil // inert
	}
	e.init(ctx)
	e.retryOpenInvoices(ctx)
	if e.BillSubscriptionsFromTable {
		e.billDueSubscriptions(ctx)
	}
	if e.DuePartners != nil && e.BuildInvoice != nil {
		e.billDuePartners(ctx)
	}
	return nil
}

func (e *SelfScheduledEngine) billDuePartners(ctx context.Context) {
	partners, err := e.DuePartners(ctx)
	if err != nil {
		e.logErr("self-scheduled: list due partners: " + err.Error())
		return
	}
	for _, pid := range partners {
		if ctx.Err() != nil {
			return
		}
		draft, err := e.BuildInvoice(ctx, pid)
		if err != nil {
			e.logErr(fmt.Sprintf("self-scheduled: build invoice for partner %d: %s", pid, err.Error()))
			continue
		}
		if draft == nil || len(draft.Lines) == 0 {
			continue
		}
		invID, err := e.createInvoice(ctx, pid, draft)
		if err != nil {
			e.logErr(fmt.Sprintf("self-scheduled: create invoice for partner %d: %s", pid, err.Error()))
			continue
		}
		e.chargeInvoice(ctx, pid, invID, draft.TotalMinor(), draft.Currency, 0, strconv.FormatInt(invID, 10), e.advanceRenewalFn(ctx, pid))
	}
}

// advanceRenewalFn is the closure-model success hook (calls AdvanceRenewal).
func (e *SelfScheduledEngine) advanceRenewalFn(ctx context.Context, partnerID int64) func() {
	return func() {
		if e.AdvanceRenewal != nil {
			if err := e.AdvanceRenewal(ctx, partnerID); err != nil {
				e.logErr(fmt.Sprintf("self-scheduled: advance renewal partner %d: %s", partnerID, err.Error()))
			}
		}
	}
}

func (e *SelfScheduledEngine) retryOpenInvoices(ctx context.Context) {
	res, err := e.qs.Query(ctx, qSSListRetryable)
	if err != nil {
		e.logErr("self-scheduled: list retryable invoices: " + err.Error())
		return
	}
	for _, row := range res.Rows {
		if ctx.Err() != nil {
			return
		}
		invID := common.AsInt64(row[0])
		partnerID := common.AsInt64(row[1])
		totalMinor := common.AsInt64(row[2]) // authoritative integer minor units
		currency := common.AsString(row[3])
		attempts := common.AsInt64(row[4])
		e.chargeInvoice(ctx, partnerID, invID, totalMinor, currency, attempts, strconv.FormatInt(invID, 10), e.advanceRenewalFn(ctx, partnerID))
	}
}

// chargeInvoice charges one invoice off-session and records the outcome.
// priorAttempts (attempt_count before this charge) decides dunning exhaustion;
// onSuccess runs after the invoice is marked paid (nil for none). idempotencyKey
// must be stable across retries of the SAME logical charge so a re-billed
// installment (still-due sub, SCA-pending) reuses the provider's PaymentIntent
// instead of creating a second charge.
func (e *SelfScheduledEngine) chargeInvoice(ctx context.Context, partnerID, invID, totalMinor int64, currency string, priorAttempts int64, idempotencyKey string, onSuccess func()) {
	customer, pm, err := e.Credentials(ctx, partnerID)
	if err != nil {
		e.markRetry(ctx, invID, "credentials: "+err.Error())
		return
	}
	res, err := e.Charge.Charge(ctx, payment.ChargeRequest{
		CustomerToken:      customer,
		PaymentMethodToken: pm,
		AmountMinor:        totalMinor,
		Currency:           currency,
		IdempotencyKey:     idempotencyKey,
		Description:        fmt.Sprintf("Invoice %d", invID),
	})
	if err != nil {
		e.markRetry(ctx, invID, err.Error()) // transport error — retry next pass
		return
	}
	switch res.Status {
	case payment.ChargeSucceeded:
		e.exec(ctx, qSSMarkPaid, res.ProviderChargeID, invID)
		if onSuccess != nil {
			onSuccess()
		}
		if e.OnPaid != nil {
			e.OnPaid(ctx, partnerID, invID)
		}
	case payment.ChargeRequiresAction:
		e.exec(ctx, qSSMarkAction, res.ProviderChargeID, invID)
		if e.OnRequiresAction != nil {
			e.OnRequiresAction(ctx, partnerID, invID, res)
		}
	default: // failed
		e.markRetry(ctx, invID, res.Error)
		if priorAttempts+1 >= int64(e.MaxAttempts) && e.Suspend != nil {
			if err := e.Suspend(ctx, partnerID); err != nil {
				e.logErr(fmt.Sprintf("self-scheduled: suspend partner %d: %s", partnerID, err.Error()))
			}
		}
		if e.OnFailed != nil {
			e.OnFailed(ctx, partnerID, invID, res)
		}
	}
}

func (e *SelfScheduledEngine) createInvoice(ctx context.Context, partnerID int64, draft *InvoiceDraft) (int64, error) {
	totalMinor := draft.TotalMinor() // authoritative; subtotal/total are major-unit display
	totalMajor := payment.MinorToMajor(totalMinor, draft.Currency)

	// Header + lines in one tx, so the charge path never sees a half-written invoice.
	tx, err := e.Repo.BeginTx(ctx, selfSchedQueries)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	id := tx.GenID()
	number := fmt.Sprintf("INV-%d", id)
	if _, err := tx.Query(ctx, qSSCreateInvoice, id, partnerID, number, totalMajor, totalMajor, totalMinor, draft.Currency); err != nil {
		return 0, err
	}
	for i, l := range draft.Lines {
		unit := payment.MinorToMajor(l.UnitPriceMinor, draft.Currency)
		amount := payment.MinorToMajor(l.UnitPriceMinor*l.Quantity, draft.Currency)
		if _, err := tx.Query(ctx, qSSInsertLine, id, i+1, l.Description, l.Quantity, unit, amount); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	committed = true
	return id, nil
}

// billDueSubscriptions charges every due subscription from its snapshot terms.
func (e *SelfScheduledEngine) billDueSubscriptions(ctx context.Context) {
	res, err := e.qs.Query(ctx, qSSListDueSubs)
	if err != nil {
		e.logErr("self-scheduled: list due subscriptions: " + err.Error())
		return
	}
	for _, row := range res.Rows {
		if ctx.Err() != nil {
			return
		}
		e.chargeDueSub(ctx, row)
	}
}

// chargeDueSub charges one due installment (row = qSSListDueSubs column order)
// and advances the sub on success.
func (e *SelfScheduledEngine) chargeDueSub(ctx context.Context, row []any) {
	partnerID := common.AsInt64(row[0])
	planID := common.AsString(row[1])
	begda := common.AsTime(row[2])
	currency := common.AsString(row[3])
	terms := BillingTerms{
		BillingCycle: ParseBillingPeriod(common.AsString(row[4])),
		TermCount:    int(common.AsInt32(row[5])),
		TermType:     ParseBillingPeriod(common.AsString(row[6])),
	}
	amountUnit := common.AsInt64(row[7])
	renewal := common.AsTime(row[8])
	nextCharge := common.AsTime(row[9])
	autoRenew := common.AsBool(row[10])

	n, err := terms.TotalInstallments()
	if err != nil {
		e.logErr(fmt.Sprintf("self-scheduled: bad terms for partner %d plan %s: %s", partnerID, planID, err.Error()))
		return
	}
	total := terms.ContractTotalMinor(amountUnit)
	// Last installment (absorbs the remainder) when one more cycle reaches term end.
	isLast := !terms.BillingCycle.NextRenewal(nextCharge).Before(renewal)
	k := 0
	if isLast {
		k = n - 1
	}
	amount := InstallmentMinor(total, n, k)

	draft := &InvoiceDraft{Currency: currency, Lines: []InvoiceLineDraft{
		{Description: fmt.Sprintf("%s subscription", planID), Quantity: 1, UnitPriceMinor: amount},
	}}
	invID, err := e.createInvoice(ctx, partnerID, draft)
	if err != nil {
		e.logErr(fmt.Sprintf("self-scheduled: create installment invoice for partner %d: %s", partnerID, err.Error()))
		return
	}
	// Stable per-installment idempotency key: while the sub stays due (SCA
	// pending or a decline being retried) every cycle mints a fresh invoice,
	// but keying the charge on the installment's due date makes the provider
	// reuse the same PaymentIntent instead of charging again.
	idemKey := fmt.Sprintf("sub:%d:%s:%d", partnerID, planID, nextCharge.Unix())
	e.chargeInvoice(ctx, partnerID, invID, amount, currency, 0, idemKey, func() {
		e.advanceSubscription(ctx, partnerID, planID, begda, terms, currency, n, renewal, nextCharge, isLast, autoRenew)
	})
}

// advanceSubscription moves the sub forward after a paid installment: bump
// next_charge_date within the term; at term end roll to a new term (re-reading
// the current price, since price locks only per term) or end the row.
func (e *SelfScheduledEngine) advanceSubscription(ctx context.Context, partnerID int64, planID string, begda time.Time, terms BillingTerms, currency string, n int, renewal, nextCharge time.Time, isLast, autoRenew bool) {
	if !isLast {
		e.exec(ctx, qSSAdvanceCharge, terms.BillingCycle.NextRenewal(nextCharge), partnerID, planID, begda)
		return
	}
	if !autoRenew {
		e.exec(ctx, qSSEndTerm, renewal, partnerID, planID, begda)
		return
	}
	res, err := e.qs.Query(ctx, qSSPlanPrice, planID, terms.BillingCycle.Code(), terms.TermType.Code(), terms.TermCount)
	if err != nil {
		e.logErr(fmt.Sprintf("self-scheduled: renew price lookup partner %d: %s", partnerID, err.Error()))
		return // leave due; retried next pass
	}
	if len(res.Rows) == 0 { // offer withdrawn — can't renew
		e.logErr(fmt.Sprintf("self-scheduled: offer withdrawn for partner %d plan %s — ending", partnerID, planID))
		e.exec(ctx, qSSEndTerm, renewal, partnerID, planID, begda)
		return
	}
	newUnit := common.AsInt64(res.Rows[0][0])
	perCharge := payment.MinorToMajor(InstallmentMinor(terms.ContractTotalMinor(newUnit), n, 0), currency)
	newRenewal := terms.TermType.AddUnits(renewal, terms.TermCount)
	e.exec(ctx, qSSRenewTerm, newRenewal, renewal, newUnit, perCharge, partnerID, planID, begda)
}

func (e *SelfScheduledEngine) markRetry(ctx context.Context, invID int64, msg string) {
	e.exec(ctx, qSSMarkRetry, msg, invID)
}

func (e *SelfScheduledEngine) exec(ctx context.Context, query string, args ...any) {
	if _, err := e.qs.Query(ctx, query, args...); err != nil {
		e.logErr(fmt.Sprintf("self-scheduled: %s: %s", query, err.Error()))
	}
}

func (e *SelfScheduledEngine) logErr(msg string) {
	if e.Journal != nil {
		e.Journal.Error(msg)
	}
}

var _ BillingEngine = (*SelfScheduledEngine)(nil)
