package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
)

// Billing read/write layer over keel's canonical basis tables
// (subscription_plan, partner_plan_subscription, usage_ledger, invoice).
// Every downstream project re-implemented these near-identical queries;
// AbstractBillingService lifts them into the framework. Project-specific
// bits — the plan catalog, the metered resource names, a custom
// plan→price map during migration — are injected, never hardcoded.
//
// The JSON tags are camelCase to match the shared sail BillingService
// model (PublicPlan / Subscription / Invoice / UsageMeter) so the Angular
// billing components consume these shapes without an adapter.

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
	BillingCycle string  `json:"billingCycle,omitempty"` // M=monthly, A=annual
	AutoRenew    bool    `json:"autoRenew"`
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

// Plan is a public catalog plan. PriceID is the provider's price/variant id
// (Stripe price_xxx), empty for free/sales-gated plans; the frontend feeds it
// to keel's CreateCheckout (validated against AllowedPriceIDs).
type Plan struct {
	ID          string  `json:"id"`
	Caption     string  `json:"caption"`
	MonthlyCost float64 `json:"monthlyCost"`
	AnnualCost  float64 `json:"annualCost"`
	Currency    string  `json:"currency"`
	PriceID     string  `json:"priceId,omitempty"`
}

// UsageItem is one resource's current-period usage vs its plan limit.
// Shape matches sail's UsageMeter (resource/used/limit).
type UsageItem struct {
	Resource string `json:"resource"`
	Used     int64  `json:"used"`
	Limit    int64  `json:"limit"`
}

// BillingService is the read/write contract every consumer's billing HTTP
// handler depends on. AbstractBillingService is the default impl; a project
// embeds it and overrides only what differs.
type BillingService interface {
	GetSubscription(ctx context.Context, partnerID int64) (*Subscription, error)
	CreateSubscription(ctx context.Context, partnerID int64, planID string) error
	CancelSubscription(ctx context.Context, partnerID int64) error
	GetInvoices(ctx context.Context, partnerID int64) ([]Invoice, error)
	GetUsage(ctx context.Context, partnerID int64) ([]UsageItem, error)
	GetPlans(ctx context.Context) ([]Plan, error)
}

// Sentinel errors so an HTTP handler can map a billing failure to a status via
// errors.Is — e.g. ErrNoSubscription → 404, ErrPlanNotFound → 400/404.
var (
	ErrNoSubscription = errors.New("no active subscription")
	ErrPlanNotFound   = errors.New("plan not found")
)

const (
	qBillGetSubscription = "bill_get_subscription"
	qBillGetPlanDetails  = "bill_get_plan_details"
	qBillCreateSub       = "bill_create_subscription"
	qBillCancelSub       = "bill_cancel_subscription"
	qBillGetInvoices     = "bill_get_invoices"
	qBillGetUsage        = "bill_get_usage"
	qBillGetQuotaLimit   = "bill_get_quota_limit"
	qBillGetAllPlans     = "bill_get_all_plans"
)

// defaultBillingQueries is pgsql-flavored (the primary dialect for keel
// consumers). A mysql consumer overrides the affected entries (e.g. the
// INTERVAL syntax in bill_create_subscription) via Queries.
var defaultBillingQueries = map[string]string{
	qBillGetSubscription: `
SELECT ps.plan_id, sp.caption, ps.status, ps.begda, ps.endda,
       ps.monthly_cost, ps.currency, ps.billing_cycle, ps.auto_renew
  FROM partner_plan_subscription ps
  JOIN subscription_plan sp ON sp.id = ps.plan_id
 WHERE ps.partner_id = ?
   AND ps.status = 'A'
   AND (ps.endda IS NULL OR ps.endda > CURRENT_TIMESTAMP)
 ORDER BY ps.begda DESC
 LIMIT 1`,

	qBillGetPlanDetails: `SELECT id FROM subscription_plan WHERE id = ? AND is_active = TRUE`,

	qBillCreateSub: `
INSERT INTO partner_plan_subscription
  (partner_id, plan_id, begda, monthly_cost, currency, status, billing_cycle, renewal_date)
SELECT ?, ?, CURRENT_TIMESTAMP, monthly_cost, currency, 'A', 'M',
       CURRENT_TIMESTAMP + INTERVAL '1 month'
  FROM subscription_plan WHERE id = ?`,

	qBillCancelSub: `
UPDATE partner_plan_subscription
   SET status = 'C', cancelled_at = CURRENT_TIMESTAMP, auto_renew = FALSE
 WHERE partner_id = ? AND status = 'A'
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

	qBillGetAllPlans: `
SELECT id, caption, monthly_cost, annual_cost, currency, provider_price_id
  FROM subscription_plan WHERE is_active = TRUE ORDER BY monthly_cost`,
}

// AbstractBillingService is the default BillingService over the basis tables.
type AbstractBillingService struct {
	Repo data.DatabaseRepository

	// Queries overrides/extends defaultBillingQueries (consumer entries win)
	// — for dialect tweaks or project-specific column lists. Read once at init.
	Queries map[string]string

	// PriceResolver maps a plan id to its provider price id. When nil, the
	// price is read from subscription_plan.provider_price_id. Inject to
	// override (e.g. a Go map during migration off provider_price_id).
	PriceResolver func(planID string) string

	// ResourceNames are the resources GetUsage reports (e.g. ["API_CALLS"]).
	ResourceNames []string

	initOnce sync.Once
	qs       data.QueryService
}

func (s *AbstractBillingService) init(ctx context.Context) {
	s.initOnce.Do(func() {
		all := make(map[string]string, len(defaultBillingQueries)+len(s.Queries))
		for k, v := range defaultBillingQueries {
			all[k] = v
		}
		for k, v := range s.Queries {
			all[k] = v
		}
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
	}, nil
}

func (s *AbstractBillingService) CreateSubscription(ctx context.Context, partnerID int64, planID string) error {
	s.init(ctx)
	res, err := s.qs.Query(ctx, qBillGetPlanDetails, planID)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("%w: %s", ErrPlanNotFound, planID)
	}
	_, err = s.qs.Query(ctx, qBillCreateSub, partnerID, planID, planID)
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
	plans := make([]Plan, len(res.Rows))
	for i, row := range res.Rows {
		id := common.AsString(row[0])
		priceID := common.AsString(row[5]) // subscription_plan.provider_price_id
		if s.PriceResolver != nil {
			priceID = s.PriceResolver(id)
		}
		plans[i] = Plan{
			ID:          id,
			Caption:     common.AsString(row[1]),
			MonthlyCost: common.AsFloat64(row[2]),
			AnnualCost:  common.AsFloat64(row[3]),
			Currency:    common.AsString(row[4]),
			PriceID:     priceID,
		}
	}
	return plans, nil
}

var _ BillingService = (*AbstractBillingService)(nil)
