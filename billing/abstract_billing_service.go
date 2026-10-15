package billing

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/payment"
	"github.com/nauticana/keel/port"
)

// Billing read/write layer over the basis tables (subscription_plan,
// partner_plan_subscription, usage_ledger, invoice). JSON tags are camelCase to
// match the sail BillingService model so Angular consumes these shapes directly.

// Subscription is a partner's active plan subscription.
type Subscription struct {
	ID               int64   `json:"id"`
	PartnerID        int64   `json:"partnerId"`
	PlanID           string  `json:"planId"`
	Caption          string  `json:"caption,omitempty"` // plan display name (from subscription_plan)
	Status           string  `json:"status"`            // A=active, P=pending, C=cancelled
	Begda            string  `json:"begda"`
	Endda            string  `json:"endda,omitempty"`
	MonthlyCost      float64 `json:"monthlyCost"` // display projection of InstallmentMinor
	InstallmentMinor int64   `json:"installmentMinor"`
	Currency         string  `json:"currency"`
	Exponent         int     `json:"exponent"`
	BillingCycle     string  `json:"billingCycle,omitempty"` // PERIOD_TYPE code copied from the plan's billing_period (M/Q/A/…)
	AutoRenew        bool    `json:"autoRenew"`
	TrialEnd         string  `json:"trialEnd"`
	Seats            int     `json:"seats"`
	ProviderManaged  bool    `json:"providerManaged"` // provider subscription and customer both exist
	// ScheduledPlanID starts at ScheduledAt, when this subscription ends.
	ScheduledPlanID string `json:"scheduledPlanId,omitempty"`
	ScheduledAt     string `json:"scheduledAt,omitempty"`
}

// Invoice is one billing invoice row (provider-issued or self-scheduled).
type Invoice struct {
	ID         int64   `json:"id,string"` // bigint ids exceed JS number precision
	Number     string  `json:"number"`
	Status     string  `json:"status"`
	Total      float64 `json:"total"` // display projection of TotalMinor
	TotalMinor int64   `json:"totalMinor"`
	Currency   string  `json:"currency"`
	Exponent   int     `json:"exponent"`
	IssuedAt   string  `json:"issuedAt"`
	PaidAt     string  `json:"paidAt,omitempty"`
}

// Plan is a public catalog plan. Prices holds one entry per offer (the
// subscription_plan_price rows) — the single source of truth for pricing.
type Plan struct {
	ID             string      `json:"id"`
	Caption        string      `json:"caption"`
	Currency       string      `json:"currency"`
	ActivationMode string      `json:"activationMode"`
	TrialDays      int         `json:"trialDays"`
	Prices         []PlanPrice `json:"prices"`
}

// PlanPrice is one purchasable offer (billing cycle + commitment term + price).
// AmountMinor is minor units for ONE term_type unit; Amount is its display-only
// major-unit projection at Exponent. PriceID is the provider price id (empty for free plans).
type PlanPrice struct {
	BillingCycle string  `json:"billingCycle"` // PERIOD_TYPE code: how often charged
	TermCount    int     `json:"termCount"`    // commitment length
	TermType     string  `json:"termType"`     // PERIOD_TYPE code: commitment/pricing unit
	AmountMinor  int64   `json:"amountMinor"`  // price per term_type unit
	Amount       float64 `json:"amount"`
	Currency     string  `json:"currency"`
	Exponent     int     `json:"exponent"`
	PriceID      string  `json:"priceId,omitempty"`
}

// UsageItem is one resource's current-period usage vs its plan limit (sail's UsageMeter).
type UsageItem struct {
	Resource string `json:"resource"`
	Caption  string `json:"caption"`
	Used     int64  `json:"used"`
	Limit    int64  `json:"limit"`
}

// Sentinels for errors.Is mapping at the handler boundary (→ 404/400).
var (
	ErrNoSubscription  = errors.New("no active subscription")
	ErrPlanNotFound    = errors.New("plan not found")
	ErrPriceNotFound   = errors.New("plan does not offer this billing interval")
	ErrUnknownResource = errors.New("usage resource is not in subscription_resource")
	ErrNotFreePlan     = errors.New("plan is not a free plan")
	// ErrProviderSubscription: the provider holds the subscription, so it must cancel it first.
	ErrProviderSubscription = errors.New("subscription is held by the payment provider")
	// ErrSubscriptionActive: the partner already holds a paid subscription; upgrades go through ChangePlan.
	ErrSubscriptionActive = errors.New("partner already has an active paid subscription")
	// ErrUnknownSubscription: a provider event names a subscription with no live local row.
	ErrUnknownSubscription = errors.New("provider subscription is not on file")
	// ErrSubscriptionPending: a pending subscription blocks starting another plan.
	ErrSubscriptionPending = errors.New("partner has a pending subscription")
)

const (
	qBillGetSubscription = "bill_get_subscription"
	qBillCreateSub       = "bill_create_subscription"
	qBillGetInvoices     = "bill_get_invoices"
	qBillGetUsage        = "bill_get_usage"
	qBillGetAllPlans     = "bill_get_all_plans"
	qBillRecordInvoice   = "bill_record_invoice"
	qBillLinkCustomer    = "bill_link_customer"
	qBillCustomerToken   = "bill_customer_token"
	qBillPartnerByCust   = "bill_partner_by_customer"
	qBillListMethods     = "bill_list_payment_methods"
	qBillActiveProvSub   = "bill_active_provider_subscription"
	qBillProviderPrice   = "bill_provider_price"
)

// defaultBillingQueries is pgsql; a mysql consumer overrides affected entries via Queries.
var defaultBillingQueries = map[string]string{
	qBillGetSubscription: `
SELECT ps.plan_id, sp.caption, ps.status, ps.begda, ps.endda, ps.installment_minor, ps.currency,
       ps.billing_cycle, ps.auto_renew, ps.trial_end, ps.seats, cur.exponent,
       COALESCE(ps.provider_subscription_id, '') <> ''
         AND EXISTS (SELECT 1 FROM partner_billing_customer bc WHERE bc.partner_id = ps.partner_id),
       ps.effective_cancel_date, COALESCE(ps.successor_plan_id, ''), sp.activation_mode
  FROM partner_plan_subscription ps
  JOIN subscription_plan sp ON sp.id = ps.plan_id
  JOIN currency cur ON cur.code = ps.currency
 WHERE ps.partner_id = ?
   AND ps.status = 'A'
   AND (ps.endda IS NULL OR ps.endda > CURRENT_TIMESTAMP)
 ORDER BY ps.begda DESC
 LIMIT 1`,

	// All billing/term/charge fields are bound from BillingTerms (computed in Go);
	// see qLcInsertActive for the column semantics.
	qBillCreateSub: `
INSERT INTO partner_plan_subscription
  (partner_id, plan_id, begda, installment_minor, currency, status, billing_cycle,
   term_count, term_type, amount_minor, renewal_date, next_charge_date)
VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 'A', ?, ?, ?, ?, ?, ?)`,

	qBillGetInvoices: `
SELECT i.id, i.invoice_number, i.total_minor, i.currency, i.status, i.issued_at, i.paid_at, cur.exponent
  FROM invoice i
  JOIN currency cur ON cur.code = i.currency
 WHERE i.partner_id = ? ORDER BY i.issued_at DESC LIMIT 50`,

	// Args: partner, period start, partner, resource.
	qBillGetUsage: `
SELECT r.caption,
       (SELECT COALESCE(SUM(ul.amount), 0) FROM usage_ledger ul
         WHERE ul.partner_id = ? AND ul.resource_name = r.id AND ul.usage_time >= ?),
       (SELECT COALESCE(MAX(sq.max_value), 0)
          FROM subscription_quota sq
          JOIN partner_plan_subscription ps ON ps.plan_id = sq.plan_id
         WHERE ps.partner_id = ? AND ps.status = 'A' AND sq.resource_id = r.id)
  FROM subscription_resource r
 WHERE r.id = ?`,

	// One row per (plan, offer); LEFT JOIN keeps plans with no price rows.
	qBillGetAllPlans: `
SELECT sp.id, sp.caption, sp.currency, sp.activation_mode, sp.trial_days,
       pp.billing_cycle, pp.term_count, pp.term_type, pp.amount_minor, pp.currency, pp.provider_price_id,
       cur.exponent
  FROM subscription_plan sp
  LEFT JOIN subscription_plan_price pp ON pp.plan_id = sp.id
  LEFT JOIN currency cur ON cur.code = pp.currency
 WHERE sp.is_active = TRUE
 ORDER BY sp.id, pp.term_type, pp.term_count, pp.billing_cycle`,

	// Written on a provider invoice.paid so GetInvoices has data. Idempotent on
	// UNIQUE invoice_number (redelivered webhook no-ops).
	qBillRecordInvoice: `
INSERT INTO invoice (id, partner_id, invoice_number, status, subtotal_minor, tax_minor, total_minor, currency, issued_at, paid_at, provider_invoice_id)
VALUES (?, ?, ?, 'P', ?, 0, ?, ?, CURRENT_TIMESTAMP, ?, ?)
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

	qBillActiveProvSub: `
SELECT COALESCE(provider_subscription_id, ''), plan_id, billing_cycle, term_type, term_count
  FROM partner_plan_subscription
 WHERE partner_id = ? AND status IN ('A', 'T', 'X')
   AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)
 ORDER BY begda DESC
 LIMIT 1`,

	qBillProviderPrice: `
SELECT COALESCE(pp.provider_price_id, '')
  FROM subscription_plan_price pp
  JOIN subscription_plan sp ON sp.id = pp.plan_id AND sp.is_active = TRUE
 WHERE pp.plan_id = ? AND pp.billing_cycle = ? AND pp.term_type = ? AND pp.term_count = ?`,
}

// AbstractBillingService is the default BillingService over the basis tables.
type AbstractBillingService struct {
	Repo port.DatabaseRepository

	// Queries overrides/extends defaultBillingQueries (consumer entries win).
	Queries map[string]string

	// ResourceNames are the resources GetUsage reports (e.g. ["API_CALLS"]).
	ResourceNames []string

	// Now is the lifecycle clock; injectable for tests (default time.Now().UTC()).
	Now func() time.Time

	// Quotas, when set, guards plan changes and drops cached limits after them.
	Quotas port.PlanQuotaService

	// FallbackPlanID is the free plan a partner moves to when a paid
	// subscription ends without a successor; empty leaves the partner without one.
	FallbackPlanID string

	initOnce   sync.Once
	qs         port.QueryService
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
	sub := &Subscription{
		PartnerID:        partnerID,
		PlanID:           common.AsString(row[0]),
		Caption:          common.AsString(row[1]),
		Status:           common.AsString(row[2]),
		Begda:            common.AsString(row[3]),
		Endda:            common.AsString(row[4]),
		InstallmentMinor: common.AsInt64(row[5]),
		Currency:         common.AsString(row[6]),
		Exponent:         int(common.AsInt64(row[11])),
		BillingCycle:     common.AsString(row[7]),
		AutoRenew:        common.AsBool(row[8]),
		TrialEnd:         common.AsString(row[9]),
		Seats:            int(common.AsInt32(row[10])),
		ProviderManaged:  common.AsBool(row[12]),
	}
	if at := common.AsString(row[13]); at != "" {
		sub.ScheduledAt = at
		sub.ScheduledPlanID = successorPlan(common.AsString(row[14]), ActivationMode(common.AsString(row[15])), s.FallbackPlanID)
	}
	if sub.MonthlyCost, err = majorAmount(sub.InstallmentMinor, sub.Exponent); err != nil {
		return nil, err
	}
	return sub, nil
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
	if _, err := s.qs.Query(ctx, qBillCreateSub,
		partnerID, planID, pc.installmentMinor, pc.currency, pc.billingCycle,
		pc.termCount, pc.termType, pc.amountUnitMinor, pc.renewalDate, now); err != nil {
		return err
	}
	s.quotasChanged(ctx, partnerID)
	return nil
}

func (s *AbstractBillingService) CancelSubscription(ctx context.Context, partnerID int64) error {
	return s.CancelByPartner(ctx, partnerID, CancelImmediate)
}

func (s *AbstractBillingService) GetInvoices(ctx context.Context, partnerID int64) ([]Invoice, error) {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qBillGetInvoices, partnerID)
	if err != nil {
		return nil, err
	}
	invoices := make([]Invoice, len(res.Rows))
	for i, row := range res.Rows {
		inv := Invoice{
			ID:         common.AsInt64(row[0]),
			Number:     common.AsString(row[1]),
			TotalMinor: common.AsInt64(row[2]),
			Currency:   common.AsString(row[3]),
			Status:     common.AsString(row[4]),
			IssuedAt:   common.AsString(row[5]),
			PaidAt:     common.AsString(row[6]),
			Exponent:   int(common.AsInt64(row[7])),
		}
		if inv.Total, err = majorAmount(inv.TotalMinor, inv.Exponent); err != nil {
			return nil, err
		}
		invoices[i] = inv
	}
	return invoices, nil
}

func (s *AbstractBillingService) GetUsage(ctx context.Context, partnerID int64) ([]UsageItem, error) {
	s.init(ctx)
	now := s.now()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	items := make([]UsageItem, 0, len(s.ResourceNames))
	for _, r := range s.ResourceNames {
		res, err := s.qs.Query(ctx, qBillGetUsage, partnerID, monthStart, partnerID, r)
		if err != nil {
			return nil, err
		}
		if len(res.Rows) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnknownResource, r)
		}
		row := res.Rows[0]
		items = append(items, UsageItem{Resource: r, Caption: common.AsString(row[0]), Used: common.AsInt64(row[1]), Limit: common.AsInt64(row[2])})
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
			Exponent:     int(common.AsInt64(row[11])),
		}
		if err := price.FillAmount(); err != nil {
			return nil, fmt.Errorf("plan %s: %w", id, err)
		}
		p.Prices = append(p.Prices, price)
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
	_, err := s.qs.Query(ctx, qBillRecordInvoice,
		s.qs.GenID(), partnerID, e.InvoiceID, e.MinorUnits, e.MinorUnits, e.Currency, e.PaidAt, e.InvoiceID)
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

func (s *AbstractBillingService) CurrentSubscription(ctx context.Context, partnerID int64) (*ProviderSubscription, error) {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qBillActiveProvSub, partnerID)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, ErrNoSubscription
	}
	row := res.Rows[0]
	return &ProviderSubscription{
		ID:     common.AsString(row[0]),
		PlanID: common.AsString(row[1]),
		Terms: BillingTerms{
			BillingCycle: ParseBillingPeriod(common.AsString(row[2])),
			TermType:     ParseBillingPeriod(common.AsString(row[3])),
			TermCount:    int(common.AsInt64(row[4])),
		},
	}, nil
}

// ProviderPriceID returns ErrPriceNotFound when the plan has no provider price on these terms.
func (s *AbstractBillingService) ProviderPriceID(ctx context.Context, planID string, terms BillingTerms) (string, error) {
	s.init(ctx)
	terms = terms.normalized()
	res, err := s.qs.Query(ctx, qBillProviderPrice, planID, terms.BillingCycle.Code(), terms.TermType.Code(), terms.TermCount)
	if err != nil {
		return "", err
	}
	if len(res.Rows) == 0 || common.AsString(res.Rows[0][0]) == "" {
		return "", fmt.Errorf("%w: plan %s has no provider price", ErrPriceNotFound, planID)
	}
	return common.AsString(res.Rows[0][0]), nil
}

func (s *AbstractBillingService) PlanActivationMode(ctx context.Context, planID string) (ActivationMode, error) {
	s.init(ctx)
	pol, err := s.loadPlanPolicy(ctx, planID)
	return pol.mode, err
}

var _ ProviderSubscriptionStore = (*AbstractBillingService)(nil)
