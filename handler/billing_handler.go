package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nauticana/keel/billing"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

// BillingHandler serves sail's BillingService paths. Without Subscriptions only
// the read routes are mounted.
type BillingHandler struct {
	AbstractHandler
	Billing       billing.BillingService
	Subscriptions billing.SubscriptionManager
}

func (h *BillingHandler) Routes() map[string]func(http.ResponseWriter, *http.Request) {
	routes := map[string]func(http.ResponseWriter, *http.Request){
		common.PublicPrefix + "/plans":              h.Plans(),
		common.RestPrefix + "/billing/subscription": h.Subscription(),
		common.RestPrefix + "/billing/invoices":     h.Invoices(),
	}
	if h.Subscriptions != nil {
		routes[common.RestPrefix+"/billing/subscription/cancel"] = h.Cancel()
		routes[common.RestPrefix+"/billing/subscription/change"] = h.ChangePlan()
		routes[common.RestPrefix+"/billing/portal"] = h.Portal()
	}
	return routes
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

// ChangePlan: POST /api/billing/subscription/change {"planId": "..."}
func (h *BillingHandler) ChangePlan() http.HandlerFunc {
	return h.JSON(http.MethodPost, func(ctx context.Context, s *model.UserSession, body json.RawMessage) (any, error) {
		partnerID, err := billingPartner(s)
		if err != nil {
			return nil, err
		}
		var req struct {
			PlanID string `json:"planId"`
		}
		if json.Unmarshal(body, &req) != nil || req.PlanID == "" {
			return nil, NewAPIError(http.StatusBadRequest, "planId is required")
		}
		if err := h.Subscriptions.ChangePlan(ctx, partnerID, req.PlanID); err != nil {
			return nil, h.subscriptionError("plan change", err)
		}
		return map[string]string{"status": "changed"}, nil
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
	switch {
	case errors.Is(err, billing.ErrNoSubscription):
		return NewAPIError(http.StatusConflict, "no active subscription")
	case errors.Is(err, billing.ErrNoProviderSubscription), errors.Is(err, billing.ErrNoProviderCustomer):
		return NewAPIError(http.StatusConflict, err.Error())
	case errors.Is(err, billing.ErrPriceNotFound), errors.Is(err, billing.ErrPlanNotFound):
		return NewAPIError(http.StatusBadRequest, "plan is not available on the current billing terms")
	}
	if h.Journal != nil {
		h.Journal.Error("billing " + action + ": " + err.Error())
	}
	return NewAPIError(http.StatusBadGateway, "billing provider unavailable")
}
