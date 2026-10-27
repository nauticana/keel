package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// BillingHandler serves sail's BillingService paths. The subscription changes
// need Subscriptions and DB, and a PARTNER_PLAN_SUBSCRIPTION grant; without
// them only the read routes are mounted.
type BillingHandler struct {
	AbstractHandler
	DB            port.DatabaseRepository
	Billing       billing.BillingService
	Subscriptions billing.SubscriptionManager
}

const (
	SubscriptionAuthObject = "PARTNER_PLAN_SUBSCRIPTION"
	subscriptionAuthScope  = "partner_plan_subscription"
)

func (h *BillingHandler) Routes() map[string]func(http.ResponseWriter, *http.Request) {
	routes := map[string]func(http.ResponseWriter, *http.Request){
		common.PublicPrefix + "/plans":              h.Plans(),
		common.RestPrefix + "/billing/subscription": h.Subscription(),
		common.RestPrefix + "/billing/invoices":     h.Invoices(),
	}
	if h.Subscriptions != nil && h.DB != nil {
		routes[common.RestPrefix+"/billing/subscription/cancel"] = h.authorize("CANCEL", h.Cancel())
		routes[common.RestPrefix+"/billing/subscription/change"] = h.authorize("CHANGE", h.ChangePlan())
		routes[common.RestPrefix+"/billing/subscription/change/check"] = h.authorize("CHANGE", h.CheckChange())
		routes[common.RestPrefix+"/billing/portal"] = h.authorize("PORTAL", h.Portal())
	}
	return routes
}

func (h *BillingHandler) authorize(action string, inner http.HandlerFunc) http.HandlerFunc {
	return WrapTableAction(h.DB, h.UserService, SubscriptionAuthObject, action, subscriptionAuthScope, inner)
}

func billingPartner(s *model.UserSession) (int64, error) {
	if s.PartnerId <= 0 {
		return 0, NewAPIError(http.StatusForbidden, "no partner in session")
	}
	return s.PartnerId, nil
}

// Plans: GET /public/plans
func (h *BillingHandler) Plans() http.HandlerFunc {
	return h.JSONPublic(http.MethodGet, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return h.Billing.GetPlans(ctx)
	})
}

// Subscription: GET /api/billing/subscription — an empty planId means none is active.
func (h *BillingHandler) Subscription() http.HandlerFunc {
	return h.JSON(http.MethodGet, func(ctx context.Context, s *model.UserSession, _ json.RawMessage) (any, error) {
		partnerID, err := billingPartner(s)
		if err != nil {
			return nil, err
		}
		sub, err := h.Billing.GetSubscription(ctx, partnerID)
		if errors.Is(err, billing.ErrNoSubscription) {
			return billing.Subscription{PartnerID: partnerID}, nil
		}
		if err != nil {
			return nil, err
		}
		return sub, nil
	})
}

// Invoices: GET /api/billing/invoices
func (h *BillingHandler) Invoices() http.HandlerFunc {
	return h.JSON(http.MethodGet, func(ctx context.Context, s *model.UserSession, _ json.RawMessage) (any, error) {
		partnerID, err := billingPartner(s)
		if err != nil {
			return nil, err
		}
		return h.Billing.GetInvoices(ctx, partnerID)
	})
}

// Cancel: POST /api/billing/subscription/cancel — renewal stops at period end.
func (h *BillingHandler) Cancel() http.HandlerFunc {
	return h.JSON(http.MethodPost, func(ctx context.Context, s *model.UserSession, _ json.RawMessage) (any, error) {
		partnerID, err := billingPartner(s)
		if err != nil {
			return nil, err
		}
		if err := h.Subscriptions.CancelAtPeriodEnd(ctx, partnerID); err != nil {
			return nil, h.subscriptionError("cancel", err)
		}
		return map[string]string{"status": "cancel_at_period_end"}, nil
	})
}

// ChangePlan: POST /api/billing/subscription/change {"planId", "billingCycle",
// "termType", "termCount"} → {"status": "changed" | "scheduled"}. Omitting the
// offer keeps the current terms.
func (h *BillingHandler) ChangePlan() http.HandlerFunc {
	return h.JSON(http.MethodPost, func(ctx context.Context, s *model.UserSession, body json.RawMessage) (any, error) {
		partnerID, err := billingPartner(s)
		if err != nil {
			return nil, err
		}
		var req struct {
			PlanID       string `json:"planId"`
			BillingCycle string `json:"billingCycle"`
			TermType     string `json:"termType"`
			TermCount    int32  `json:"termCount"`
		}
		if common.DecodeJSON(body, &req) != nil || req.PlanID == "" {
			return nil, NewAPIError(http.StatusBadRequest, "planId is required")
		}
		terms, err := changeTerms(req.BillingCycle, req.TermType, int(req.TermCount))
		if err != nil {
			return nil, err
		}
		outcome, err := h.Subscriptions.ChangePlan(ctx, partnerID, req.PlanID, terms)
		if err != nil {
			return nil, h.subscriptionError("plan change", err)
		}
		return map[string]string{"status": string(outcome)}, nil
	})
}

// changeTerms reads an offer whose billingCycle and termType come together;
// termCount 0 means one term. None of the three keeps the current terms.
func changeTerms(cycle, termType string, count int) (billing.BillingTerms, error) {
	if cycle == "" && termType == "" && count == 0 {
		return billing.BillingTerms{}, nil
	}
	terms := billing.BillingTerms{BillingCycle: billing.BillingPeriod(cycle), TermType: billing.BillingPeriod(termType), TermCount: count}
	if !terms.BillingCycle.Valid() || !terms.TermType.Valid() || count < 0 {
		return billing.BillingTerms{}, NewAPIError(http.StatusBadRequest, "billingCycle and termType must be period codes and termCount must not be negative")
	}
	return terms, nil
}

// CheckChange: POST /api/billing/subscription/change/check {"planId": "..."} →
// {"overages": [{resource, count, limit}]}, empty when the change is allowed.
func (h *BillingHandler) CheckChange() http.HandlerFunc {
	return h.JSON(http.MethodPost, func(ctx context.Context, s *model.UserSession, body json.RawMessage) (any, error) {
		partnerID, err := billingPartner(s)
		if err != nil {
			return nil, err
		}
		var req struct {
			PlanID string `json:"planId"`
		}
		if common.DecodeJSON(body, &req) != nil || req.PlanID == "" {
			return nil, NewAPIError(http.StatusBadRequest, "planId is required")
		}
		overages, err := h.Subscriptions.CheckChange(ctx, partnerID, req.PlanID)
		if err != nil {
			return nil, h.subscriptionError("change check", err)
		}
		if overages == nil {
			overages = []port.QuotaOverage{}
		}
		return map[string]any{"overages": overages}, nil
	})
}

// Portal: POST /api/billing/portal
func (h *BillingHandler) Portal() http.HandlerFunc {
	return h.JSON(http.MethodPost, func(ctx context.Context, s *model.UserSession, _ json.RawMessage) (any, error) {
		partnerID, err := billingPartner(s)
		if err != nil {
			return nil, err
		}
		url, err := h.Subscriptions.PortalURL(ctx, partnerID)
		if err != nil {
			return nil, h.subscriptionError("portal", err)
		}
		return map[string]string{"portalUrl": url}, nil
	})
}

func (h *BillingHandler) subscriptionError(action string, err error) error {
	if over, ok := errors.AsType[*billing.OverTargetLimitError](err); ok {
		return &APIError{Status: http.StatusConflict, Msg: "remove what the plan does not allow before changing to it", Details: over.Overages}
	}
	switch {
	case errors.Is(err, billing.ErrNoSubscription):
		return NewAPIError(http.StatusConflict, "no active subscription")
	case errors.Is(err, billing.ErrNoProviderSubscription), errors.Is(err, billing.ErrNoProviderCustomer),
		errors.Is(err, billing.ErrSubscriptionPending), errors.Is(err, billing.ErrProviderSubscription):
		return NewAPIError(http.StatusConflict, err.Error())
	case errors.Is(err, billing.ErrPriceNotFound), errors.Is(err, billing.ErrPlanNotFound), errors.Is(err, billing.ErrNotFreePlan):
		return NewAPIError(http.StatusBadRequest, "plan is not offered on these billing terms")
	}
	if h.Journal != nil {
		h.Journal.Error("billing " + action + ": " + err.Error())
	}
	return NewAPIError(http.StatusBadGateway, "billing provider unavailable")
}
