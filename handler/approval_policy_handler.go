package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/nauticana/keel/approval"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// ApprovalPolicies is what ApprovalPolicyHandler needs from approval.Service.
type ApprovalPolicies interface {
	SetPolicy(ctx context.Context, p approval.Policy) (bool, error)
	ConfirmPolicy(ctx context.Context, partnerID int64, objectType string, confirmerID int64) error
	OpenPolicies(ctx context.Context, partnerID int64) ([]approval.OpenPolicy, error)
}

var _ ApprovalPolicies = (*approval.Service)(nil)

// ApprovalPolicyHandler changes the separation-of-duties policy of the
// session partner and of the platform; approval.Service decides who is an
// administrator of either.
type ApprovalPolicyHandler struct {
	AbstractHandler
	DB       port.DatabaseRepository
	Policies ApprovalPolicies
}

type approvalPolicyChange struct {
	ObjectType        string `json:"objectType"`
	AllowSinglePerson bool   `json:"allowSinglePerson"`
}

// Routes mounts, under apiPrefix, approval_policy/set and confirm gated by
// APPROVAL_POLICY CHANGE, and set_platform, confirm_platform and platform
// gated by APPROVAL_POLICY CHANGE_PLATFORM.
func (h *ApprovalPolicyHandler) Routes(apiPrefix string) map[string]func(http.ResponseWriter, *http.Request) {
	routes := map[string]func(http.ResponseWriter, *http.Request){}
	mount := func(name, action, method string, fn JSONFunc) {
		routes[TableActionPath(apiPrefix, "approval_policy", name)] = WrapTableAction(
			h.DB, h.UserService, "APPROVAL_POLICY", action, "approval_policy", h.JSON(method, fn))
	}
	mount("set", "CHANGE", http.MethodPost, h.Set)
	mount("confirm", "CHANGE", http.MethodPost, h.Confirm)
	mount("set_platform", "CHANGE_PLATFORM", http.MethodPost, h.SetPlatform)
	mount("confirm_platform", "CHANGE_PLATFORM", http.MethodPost, h.ConfirmPlatform)
	mount("platform", "CHANGE_PLATFORM", http.MethodGet, h.Platform)
	return routes
}

// Set takes {objectType, allowSinglePerson} for the session partner and
// answers with the change; inForce is false while it awaits another
// administrator's confirmation.
func (h *ApprovalPolicyHandler) Set(ctx context.Context, session *model.UserSession, body json.RawMessage) (any, error) {
	partnerID, err := h.SessionPartner(session)
	if err != nil {
		return nil, err
	}
	return h.set(ctx, partnerID, session, body)
}

// Confirm takes {objectType} and puts the change another administrator of
// the session partner set in force.
func (h *ApprovalPolicyHandler) Confirm(ctx context.Context, session *model.UserSession, body json.RawMessage) (any, error) {
	partnerID, err := h.SessionPartner(session)
	if err != nil {
		return nil, err
	}
	return h.confirm(ctx, partnerID, session, body)
}

// SetPlatform is Set for the platform's policy.
func (h *ApprovalPolicyHandler) SetPlatform(ctx context.Context, session *model.UserSession, body json.RawMessage) (any, error) {
	return h.set(ctx, 0, session, body)
}

// ConfirmPlatform is Confirm for the platform's policy.
func (h *ApprovalPolicyHandler) ConfirmPlatform(ctx context.Context, session *model.UserSession, body json.RawMessage) (any, error) {
	return h.confirm(ctx, 0, session, body)
}

// Platform lists the platform's open rules.
func (h *ApprovalPolicyHandler) Platform(ctx context.Context, _ *model.UserSession, _ json.RawMessage) (any, error) {
	if h.Policies == nil {
		return nil, errApprovalPolicyNotConfigured
	}
	return h.Policies.OpenPolicies(ctx, 0)
}

var errApprovalPolicyNotConfigured = NewAPIError(http.StatusInternalServerError, "approval policy handler not configured")

func (h *ApprovalPolicyHandler) set(ctx context.Context, partnerID int64, session *model.UserSession, body json.RawMessage) (any, error) {
	req, err := h.read(body)
	if err != nil {
		return nil, err
	}
	inForce, err := h.Policies.SetPolicy(ctx, approval.Policy{PartnerID: partnerID, ObjectType: req.ObjectType,
		AllowSinglePerson: req.AllowSinglePerson, ChangedBy: int64(session.Id)})
	if err != nil {
		return nil, err
	}
	return approval.OpenPolicy{ObjectType: req.ObjectType, AllowSinglePerson: req.AllowSinglePerson, InForce: inForce}, nil
}

// Only allowing a single person waits for confirmation.
func (h *ApprovalPolicyHandler) confirm(ctx context.Context, partnerID int64, session *model.UserSession, body json.RawMessage) (any, error) {
	req, err := h.read(body)
	if err != nil {
		return nil, err
	}
	if err := h.Policies.ConfirmPolicy(ctx, partnerID, req.ObjectType, int64(session.Id)); err != nil {
		return nil, err
	}
	return approval.OpenPolicy{ObjectType: req.ObjectType, AllowSinglePerson: true, InForce: true}, nil
}

func (h *ApprovalPolicyHandler) read(body json.RawMessage) (approvalPolicyChange, error) {
	var req approvalPolicyChange
	if h.Policies == nil {
		return req, errApprovalPolicyNotConfigured
	}
	if common.DecodeJSON(body, &req) != nil || req.ObjectType == "" {
		return req, NewAPIError(http.StatusBadRequest, "objectType is required")
	}
	return req, nil
}
