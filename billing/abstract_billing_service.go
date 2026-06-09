package billing

import (
	"context"
	"errors"
	"maps"
	"strconv"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/payment"
)

// Billing read/write layer over the basis tables (subscription_plan,
// partner_plan_subscription, usage_ledger, invoice). JSON tags are camelCase to
// match the sail BillingService model so Angular consumes these shapes directly.

// Subscription is a partner's active plan subscription.
type Subscription struct {
	ID           int64   `json:"id"`
	PartnerID    int64   `json:"partnerId"`
	PlanID       string  `json:"planId"`
	Caption      string  `json:"caption,omitempty"` // plan display name (from subscription_plan)
	Status       string  `json:"status"`            // A=active, P=pending, C=cancelled
	Begda        string  `json:"begda"`
	Endda        string  `json:"endda,omitempty"`
	MonthlyCost  float64 `json:"monthlyCost"`
	Currency     string  `json:"currency"`
	BillingCycle string  `json:"billingCycle,omitempty"` // PERIOD_TYPE code copied from the plan's billing_period (M/Q/A/…)
	AutoRenew    bool    `json:"autoRenew"`
	TrialEnd     string  `json:"trialEnd"`
	Seats        int     `json:"seats"`
}

// Invoice is one billing invoice row (provider-issued or self-scheduled).
type Invoice struct {
	ID       int64   `json:"id"`
	Number   string  `json:"number"`
	Status   string  `json:"status"`
	Total    float64 `json:"total"`
	Currency string  `json:"currency"`
	IssuedAt string  `json:"issuedAt"`
	PaidAt   string  `json:"paidAt,omitempty"`
}

// Plan is a public catalog plan. Prices holds one entry per offer (the
// subscription_plan_price rows); MonthlyCost/AnnualCost are convenience
// projections of the 1-unit M/A rows for the sail display contract.
type Plan struct {
	ID             string      `json:"id"`
	Caption        string      `json:"caption"`
	MonthlyCost    float64     `json:"monthlyCost"`
	AnnualCost     float64     `json:"annualCost"`
	Currency       string      `json:"currency"`
	ActivationMode string      `json:"activationMode"`
	TrialDays      int         `json:"trialDays"`
	Prices         []PlanPrice `json:"prices"`
}

// PlanPrice is one purchasable offer (billing cycle + commitment term + price).
// AmountMinor is authoritative minor units for ONE term_type unit; Amount is its
// major-unit projection. PriceID is the provider price id (empty for free plans).
type PlanPrice struct {
	BillingCycle string  `json:"billingCycle"` // PERIOD_TYPE code: how often charged
	TermCount    int     `json:"termCount"`    // commitment length
	TermType     string  `json:"termType"`     // PERIOD_TYPE code: commitment/pricing unit
	AmountMinor  int64   `json:"amountMinor"`  // price per term_type unit
	Amount       float64 `json:"amount"`
	Currency     string  `json:"currency"`
	PriceID      string  `json:"priceId,omitempty"`
}

// UsageItem is one resource's current-period usage vs its plan limit (sail's UsageMeter).
type UsageItem struct {
	Resource string `json:"resource"`
	Used     int64  `json:"used"`
	Limit    int64  `json:"limit"`
}

// Sentinels for errors.Is mapping at the handler boundary (→ 404/400).
var (
	ErrNoSubscription = errors.New("no active subscription")
	ErrPlanNotFound   = errors.New("plan not found")
	ErrPriceNotFound  = errors.New("plan does not offer this billing interval")
)

const (
	qBillGetSubscription = "bill_get_subscription"
	qBillCreateSub       = "bill_create_subscription"
	qBillCancelSub       = "bill_cancel_subscription"
	qBillGetInvoices     = "bill_get_invoices"
	qBillGetUsage        = "bill_get_usage"
	qBillGetQuotaLimit   = "bill_get_quota_limit"
	qBillGetAllPlans     = "bill_get_all_plans"
	qBillRecordInvoice   = "bill_record_invoice"
	qBillLinkCustomer    = "bill_link_customer"
	qBillCustomerToken   = "bill_customer_token"
	qBillPartnerByCust   = "bill_partner_by_customer"
	qBillListMethods     = "bill_list_payment_methods"
)

// defaultBillingQueries is pgsql; a mysql consumer overrides affected entries via Queries.
var defaultBillingQueries = map[string]string{
	qBillGetSubscription: `
SELECT ps.plan_id, sp.caption, ps.status, ps.begda, ps.endda, ps.monthly_cost, ps.currency,
       ps.billing_cycle, ps.auto_renew, ps.trial_end, ps.seats
  FROM partner_plan_subscription ps
  JOIN subscription_plan sp ON sp.id = ps.plan_id
 WHERE ps.partner_id = ?
   AND ps.status = 'A'
   AND (ps.endda IS NULL OR ps.endda > CURRENT_TIMESTAMP)
 ORDER BY ps.begda DESC
 LIMIT 1`,

	// All billing/term/charge fields are bound from BillingTerms (computed in Go);
	// see qLcInsertActive for the column semantics.
	qBillCreateSub: `
INSERT INTO partner_plan_subscription
  (partner_id, plan_id, begda, monthly_cost, currency, status, billing_cycle,
   term_count, term_type, amount_minor, renewal_date, next_charge_date)
VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 'A', ?, ?, ?, ?, ?, ?)`,

	qBillCancelSub: `
UPDATE partner_plan_subscription
   SET status = 'C', cancelled_at = CURRENT_TIMESTAMP, auto_renew = FALSE
 WHERE partner_id = ? AND status IN ('A', 'T')
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)`,

	qBillGetInvoices: `
SELECT id, invoice_number, total, currency, status, issued_at, paid_at
  FROM invoice WHERE partner_id = ? ORDER BY issued_at DESC LIMIT 50`,

	qBillGetUsage: `
SELECT COALESCE(SUM(amount), 0) FROM usage_ledger
 WHERE partner_id = ? AND resource_name = ? AND usage_time >= ?`,

	qBillGetQuotaLimit: `
SELECT COALESCE(MAX(sq.max_value), 0)
  FROM subscription_quota sq, partner_plan_subscription ps
 WHERE ps.partner_id = ? AND ps.status = 'A'
   AND sq.plan_id = ps.plan_id AND sq.resource_id = ?`,

	// One row per (plan, offer); LEFT JOIN keeps plans with no price rows.
	qBillGetAllPlans: `
SELECT sp.id, sp.caption, sp.currency, sp.activation_mode, sp.trial_days,
       pp.billing_cycle, pp.term_count, pp.term_type, pp.amount_minor, pp.currency, pp.provider_price_id
  FROM subscription_plan sp
  LEFT JOIN subscription_plan_price pp ON pp.plan_id = sp.id
 WHERE sp.is_active = TRUE
 ORDER BY sp.id, pp.term_type, pp.term_count, pp.billing_cycle`,

	// Written on a provider invoice.paid so GetInvoices has data. Idempotent on
	// UNIQUE invoice_number (redelivered webhook no-ops).
	qBillRecordInvoice: `
INSERT INTO invoice (id, partner_id, invoice_number, status, subtotal, tax, total, total_minor, currency, issued_at, paid_at, provider_invoice_id)
VALUES (?, ?, ?, 'P', ?, 0, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
ON CONFLICT (invoice_number) DO NOTHING`,

	// Partner ↔ provider-customer token; idempotent on the composite PK.
	qBillLinkCustomer: `
INSERT INTO partner_billing_customer (partner_id, provider, customer_token)
VALUES (?, ?, ?)
ON CONFLICT (partner_id, provider) DO NOTHING`,

	qBillCustomerToken: `
SELECT customer_token FROM partner_billing_customer
 WHERE partner_id = ? AND provider = ?`,

	qBillPartnerByCust: `
SELECT partner_id FROM partner_billing_customer
 WHERE provider = ? AND customer_token = ?`,

	qBillListMethods: `
SELECT id, provider, method_type, is_default FROM payment_method
 WHERE partner_id = ? ORDER BY is_default DESC, id`,
}

// AbstractBillingService is the default BillingService over the basis tables.
type AbstractBillingService struct {
	Repo data.DatabaseRepository

	// Queries overrides/extends defaultBillingQueries (consumer entries win).
	Queries map[string]string

	// ResourceNames are the resources GetUsage reports (e.g. ["API_CALLS"]).
	ResourceNames []string

	// Now is the lifecycle clock; injectable for tests (default time.Now().UTC()).
	Now func() time.Time

	initOnce   sync.Once
	qs         data.QueryService
	allQueries map[string]string // merged default+lifecycle+override, reused by BeginTx
}

func (s *AbstractBillingService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *AbstractBillingService) init(ctx context.Context) {
	s.initOnce.Do(func() {
		all := make(map[string]string, len(defaultBillingQueries)+len(lifecycleQueries)+len(s.Queries))
		maps.Copy(all, defaultBillingQueries)
		maps.Copy(all, lifecycleQueries)
		maps.Copy(all, s.Queries)
		s.allQueries = all
		s.qs = s.Repo.GetQueryService(ctx, all)
	})
}

func (s *AbstractBillingService) GetSubscription(ctx context.Context, partnerID int64) (*Subscription, error) {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qBillGetSubscription, partnerID)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, ErrNoSubscription
	}
	row := res.Rows[0]
	return &Subscription{
		PartnerID:    partnerID,
		PlanID:       common.AsString(row[0]),
		Caption:      common.AsString(row[1]),
		Status:       common.AsString(row[2]),
		Begda:        common.AsString(row[3]),
		Endda:        common.AsString(row[4]),
		MonthlyCost:  common.AsFloat64(row[5]),
		Currency:     common.AsString(row[6]),
		BillingCycle: common.AsString(row[7]),
		AutoRenew:    common.AsString(row[8]) == "true" || common.AsInt64(row[8]) == 1,
		TrialEnd:     common.AsString(row[9]),
		Seats:        int(common.AsInt32(row[10])),
	}, nil
}

func (s *AbstractBillingService) CreateSubscription(ctx context.Context, partnerID int64, planID string, terms BillingTerms) error {
	s.init(ctx)
	if _, err := s.loadPlanPolicy(ctx, planID); err != nil { // validates the plan exists/active
		return err
	}
	now := s.now()
	pc, err := s.loadPlanCharge(ctx, planID, terms, now)
	if err != nil {
		return err
	}
	_, err = s.qs.Query(ctx, qBillCreateSub,
		partnerID, planID, pc.perChargeMajor, pc.currency, pc.billingCycle,
		pc.termCount, pc.termType, pc.amountUnitMinor, pc.renewalDate, now)
	return err
}

func (s *AbstractBillingService) CancelSubscription(ctx context.Context, partnerID int64) error {
	s.init(ctx)
	_, err := s.qs.Query(ctx, qBillCancelSub, partnerID)
	return err
}

func (s *AbstractBillingService) GetInvoices(ctx context.Context, partnerID int64) ([]Invoice, error) {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qBillGetInvoices, partnerID)
	if err != nil {
		return nil, err
	}
	invoices := make([]Invoice, len(res.Rows))
	for i, row := range res.Rows {
		invoices[i] = Invoice{
			ID:       common.AsInt64(row[0]),
			Number:   common.AsString(row[1]),
			Total:    common.AsFloat64(row[2]),
			Currency: common.AsString(row[3]),
			Status:   common.AsString(row[4]),
			IssuedAt: common.AsString(row[5]),
			PaidAt:   common.AsString(row[6]),
		}
	}
	return invoices, nil
}

func (s *AbstractBillingService) GetUsage(ctx context.Context, partnerID int64) ([]UsageItem, error) {
	s.init(ctx)
	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	items := make([]UsageItem, 0, len(s.ResourceNames))
	for _, r := range s.ResourceNames {
		item := UsageItem{Resource: r}
		usedRes, err := s.qs.Query(ctx, qBillGetUsage, partnerID, r, monthStart)
		if err != nil {
			return nil, err
		}
		if len(usedRes.Rows) > 0 {
			item.Used = common.AsInt64(usedRes.Rows[0][0])
		}
		limRes, err := s.qs.Query(ctx, qBillGetQuotaLimit, partnerID, r)
		if err != nil {
			return nil, err
		}
		if len(limRes.Rows) > 0 {
			item.Limit = common.AsInt64(limRes.Rows[0][0])
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *AbstractBillingService) GetPlans(ctx context.Context) ([]Plan, error) {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qBillGetAllPlans)
	if err != nil {
		return nil, err
	}
	// One row per (plan, price); group by plan id, preserving query order.
	order := make([]string, 0, len(res.Rows))
	byID := make(map[string]*Plan, len(res.Rows))
	for _, row := range res.Rows {
		id := common.AsString(row[0])
		p, ok := byID[id]
		if !ok {
			p = &Plan{
				ID:             id,
				Caption:        common.AsString(row[1]),
				Currency:       common.AsString(row[2]),
				ActivationMode: common.AsString(row[3]),
				TrialDays:      int(common.AsInt32(row[4])),
			}
			byID[id] = p
			order = append(order, id)
		}
		billing := common.AsString(row[5]) // empty when the plan has no price rows (LEFT JOIN)
		if billing == "" {
			continue
		}
		price := PlanPrice{
			BillingCycle: billing,
			TermCount:    int(common.AsInt32(row[6])),
			TermType:     common.AsString(row[7]),
			AmountMinor:  common.AsInt64(row[8]),
			Currency:     common.AsString(row[9]),
			PriceID:      common.AsString(row[10]),
		}
		price.Amount = payment.MinorToMajor(price.AmountMinor, price.Currency)
		p.Prices = append(p.Prices, price)
		// Convenience headline projections (per-unit price for a 1-unit term).
		if price.TermCount == 1 {
			switch ParseBillingPeriod(price.TermType) {
			case PeriodMonthly:
				p.MonthlyCost = price.Amount
			case PeriodAnnual:
				p.AnnualCost = price.Amount
			}
		}
	}
	plans := make([]Plan, len(order))
	for i, id := range order {
		plans[i] = *byID[id]
	}
	return plans, nil
}

// PaymentMethodInfo is sail's PaymentMethod shape. ID is a string because the
// bigint payment_method.id overflows JS number precision.
type PaymentMethodInfo struct {
	ID         string `json:"id"`
	Provider   string `json:"provider"`
	MethodType string `json:"methodType"`
	IsDefault  bool   `json:"isDefault"`
}

// RecordProviderInvoice persists the invoice row on a provider invoice.paid so
// GetInvoices has data. No-op without an invoice id; idempotent on invoice_number.
func (s *AbstractBillingService) RecordProviderInvoice(ctx context.Context, partnerID int64, e *payment.PaymentEvent) error {
	if e == nil || e.InvoiceID == "" {
		return nil
	}
	s.init(ctx)
	major := payment.MinorToMajor(e.MinorUnits, e.Currency)
	_, err := s.qs.Query(ctx, qBillRecordInvoice,
		s.qs.GenID(), partnerID, e.InvoiceID, major, major, e.MinorUnits, e.Currency, e.PaidAt, e.InvoiceID)
	return err
}

// LinkCustomer idempotently stores the partner ↔ provider-customer token. No-op
// on an empty token.
func (s *AbstractBillingService) LinkCustomer(ctx context.Context, partnerID int64, provider, customerToken string) error {
	if customerToken == "" {
		return nil
	}
	s.init(ctx)
	_, err := s.qs.Query(ctx, qBillLinkCustomer, partnerID, provider, customerToken)
	return err
}

// CustomerToken returns the partner's provider-customer token, or "" when none
// is stored (e.g. the partner hasn't completed a checkout yet).
func (s *AbstractBillingService) CustomerToken(ctx context.Context, partnerID int64, provider string) (string, error) {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qBillCustomerToken, partnerID, provider)
	if err != nil || len(res.Rows) == 0 {
		return "", err
	}
	return common.AsString(res.Rows[0][0]), nil
}

// PartnerByCustomer is the reverse lookup recurring-invoice webhooks need (no
// metadata). Returns 0 when unknown.
func (s *AbstractBillingService) PartnerByCustomer(ctx context.Context, provider, customerToken string) (int64, error) {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qBillPartnerByCust, provider, customerToken)
	if err != nil || len(res.Rows) == 0 {
		return 0, err
	}
	return common.AsInt64(res.Rows[0][0]), nil
}

// ListPaymentMethods returns the partner's saved provider methods (sail's listPaymentMethods()).
func (s *AbstractBillingService) ListPaymentMethods(ctx context.Context, partnerID int64) ([]PaymentMethodInfo, error) {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qBillListMethods, partnerID)
	if err != nil {
		return nil, err
	}
	out := make([]PaymentMethodInfo, len(res.Rows))
	for i, row := range res.Rows {
		out[i] = PaymentMethodInfo{
			ID:         strconv.FormatInt(common.AsInt64(row[0]), 10),
			Provider:   common.AsString(row[1]),
			MethodType: common.AsString(row[2]),
			IsDefault:  common.AsBool(row[3]),
		}
	}
	return out, nil
}

var _ BillingService = (*AbstractBillingService)(nil)
var _ ProviderBillingStore = (*AbstractBillingService)(nil)
