package service

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/payment"
)

// BillingEngine is the swappable recurring-billing strategy. ProviderSubscriptionEngine
// lets the provider (Stripe Billing / LemonSqueezy) run the cycle and reacts to
// webhooks; SelfScheduledEngine runs the cycle itself on a schedule and charges
// off-session. A project picks one per deployment (or per plan); the shared parts
// (the invoice row, the notification path) are common to both.
type BillingEngine interface {
	// EnsureSubscription makes sure the partner has an active subscription for
	// the plan. Provider-driven: the checkout + webhook flow handles it (no-op
	// here). Self-scheduled: the project creates the local subscription row.
	EnsureSubscription(ctx context.Context, partnerID int64, planID string) error
	// HandleEvent reacts to a provider webhook event. Provider-driven only.
	HandleEvent(ctx context.Context, e *payment.PaymentEvent) error
	// RunCycle runs one billing pass (dunning retries + new-period charges).
	// Self-scheduled only; a no-op for provider-driven.
	RunCycle(ctx context.Context) error
}

// ProviderSubscriptionEngine delegates the cycle to the payment provider and
// reacts to its webhooks via the injected AbstractWebhookEventHandler.
type ProviderSubscriptionEngine struct {
	Handler *payment.AbstractWebhookEventHandler
}

func (e *ProviderSubscriptionEngine) EnsureSubscription(ctx context.Context, partnerID int64, planID string) error {
	return nil // provider checkout + webhook activates the subscription
}

func (e *ProviderSubscriptionEngine) HandleEvent(ctx context.Context, ev *payment.PaymentEvent) error {
	if e.Handler == nil {
		return nil
	}
	return e.Handler.OnPaymentEvent(ctx, ev)
}

func (e *ProviderSubscriptionEngine) RunCycle(ctx context.Context) error { return nil }

var _ BillingEngine = (*ProviderSubscriptionEngine)(nil)

// InvoiceLineDraft / InvoiceDraft describe the period invoice a project computes
// for a partner. Amounts are minor currency units (e.g. cents).
type InvoiceLineDraft struct {
	Description    string
	Quantity       int64
	UnitPriceMinor int64
}

type InvoiceDraft struct {
	Currency string
	Lines    []InvoiceLineDraft
}

func (d *InvoiceDraft) TotalMinor() int64 {
	var t int64
	for _, l := range d.Lines {
		t += l.UnitPriceMinor * l.Quantity
	}
	return t
}

const (
	qSSCreateInvoice = "ss_create_invoice"
	qSSInsertLine    = "ss_insert_line"
	qSSMarkPaid      = "ss_mark_paid"
	qSSMarkAction    = "ss_mark_action_required"
	qSSMarkRetry     = "ss_mark_retry"
	qSSListRetryable = "ss_list_retryable"
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

	// Open invoices that have already been attempted and are due for a retry.
	qSSListRetryable: `
SELECT id, partner_id, total_minor, currency, attempt_count
  FROM invoice
 WHERE status = 'O' AND attempt_count > 0
   AND (next_attempt_at IS NULL OR next_attempt_at <= CURRENT_TIMESTAMP)
 ORDER BY id`,
}

// SelfScheduledEngine runs the billing cycle itself: it builds a period invoice
// per due partner, charges it off-session against a vaulted payment method, and
// handles the outcome (paid / SCA-required / dunning). It is INERT until the
// project-specific closures are wired — a deploy that leaves them nil does
// nothing. MUST be tested exhaustively in provider test mode before enabling.
type SelfScheduledEngine struct {
	Repo        data.DatabaseRepository
	Charge      payment.ChargeClient
	Journal     logger.ApplicationLogger
	MaxAttempts int // dunning: suspend after this many failed attempts (default 3)

	// DuePartners returns partner ids due for a NEW billing period now.
	DuePartners func(ctx context.Context) ([]int64, error)
	// BuildInvoice computes the period invoice for a partner. Return (nil, nil)
	// to skip (nothing to bill this period).
	BuildInvoice func(ctx context.Context, partnerID int64) (*InvoiceDraft, error)
	// Credentials resolves the partner's vaulted provider customer + payment
	// method tokens.
	Credentials func(ctx context.Context, partnerID int64) (customer, paymentMethod string, err error)
	// AdvanceRenewal advances the partner's subscription renewal_date after a
	// successful charge (the project owns the interval).
	AdvanceRenewal func(ctx context.Context, partnerID int64) error
	// Suspend marks the partner past_due/unpaid after dunning exhaustion.
	Suspend func(ctx context.Context, partnerID int64) error
	// OnRequiresAction notifies the partner to complete SCA (res carries the
	// PaymentIntent client_secret / action URL).
	OnRequiresAction func(ctx context.Context, partnerID, invoiceID int64, res payment.ChargeResult)
	// OnPaid / OnFailed are optional notification hooks.
	OnPaid   func(ctx context.Context, partnerID, invoiceID int64)
	OnFailed func(ctx context.Context, partnerID, invoiceID int64, res payment.ChargeResult)

	initOnce sync.Once
	qs       data.QueryService
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

// RunCycle runs one billing pass: first retry the open (dunning) invoices, then
// bill the partners due for a new period. Inert until the required closures are
// wired.
func (e *SelfScheduledEngine) RunCycle(ctx context.Context) error {
	if e.Charge == nil || e.Credentials == nil {
		return nil // not configured — inert
	}
	e.init(ctx)
	e.retryOpenInvoices(ctx)
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
		e.chargeInvoice(ctx, pid, invID, draft.TotalMinor(), draft.Currency, 0)
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
		e.chargeInvoice(ctx, partnerID, invID, totalMinor, currency, attempts)
	}
}

// chargeInvoice charges one invoice off-session and records the outcome.
// priorAttempts is the invoice's attempt_count before this charge (0 for a
// fresh invoice) — used to decide dunning exhaustion.
func (e *SelfScheduledEngine) chargeInvoice(ctx context.Context, partnerID, invID, totalMinor int64, currency string, priorAttempts int64) {
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
		IdempotencyKey:     strconv.FormatInt(invID, 10),
		Description:        fmt.Sprintf("Invoice %d", invID),
	})
	if err != nil {
		// transport error — leave open, schedule a retry next pass
		e.markRetry(ctx, invID, err.Error())
		return
	}
	switch res.Status {
	case payment.ChargeSucceeded:
		e.exec(ctx, qSSMarkPaid, res.ProviderChargeID, invID)
		if e.AdvanceRenewal != nil {
			if err := e.AdvanceRenewal(ctx, partnerID); err != nil {
				e.logErr(fmt.Sprintf("self-scheduled: advance renewal partner %d: %s", partnerID, err.Error()))
			}
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
	totalMinor := draft.TotalMinor()
	// total_minor is the authoritative amount charged; subtotal/total are the
	// human-readable major-unit projection (currency-aware, not a hardcoded /100
	// — JPY has 0 minor digits, BHD has 3).
	totalMajor := payment.MinorToMajor(totalMinor, draft.Currency)

	// Header + lines are one atomic unit: a committed invoice always carries its
	// full line set, so the charge path can never bill a half-written invoice.
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
			return 0, err // tx rolls back via defer — no half-written invoice survives
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	committed = true
	return id, nil
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
