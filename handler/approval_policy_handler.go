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
}

var _ ApprovalPolicies = (*approval.Service)(nil)

// ApprovalPolicyHandler changes the session partner's separation-of-duties
// policy; approval.Service decides who is an administrator.
type ApprovalPolicyHandler struct {
	AbstractHandler
	DB       port.DatabaseRepository
	Policies ApprovalPolicies
}

type approvalPolicyChange struct {
	ObjectType        string `json:"objectType"`
	AllowSinglePerson bool   `json:"allowSinglePerson"`
}

// Routes mounts approval_policy/set and approval_policy/confirm under
// apiPrefix, both gated by APPROVAL_POLICY CHANGE.
func (h *ApprovalPolicyHandler) Routes(apiPrefix string) map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		TableActionPath(apiPrefix, "approval_policy", "set"): WrapTableAction(
			h.DB, h.UserService, "APPROVAL_POLICY", "CHANGE", "approval_policy", h.JSON(http.MethodPost, h.Set)),
		TableActionPath(apiPrefix, "approval_policy", "confirm"): WrapTableAction(
			h.DB, h.UserService, "APPROVAL_POLICY", "CHANGE", "approval_policy", h.JSON(http.MethodPost, h.Confirm)),
	}
}

// Set takes {objectType, allowSinglePerson} and answers with the change and
// inForce, false while it awaits another administrator's confirmation.
func (h *ApprovalPolicyHandler) Set(ctx context.Context, session *model.UserSession, body json.RawMessage) (any, error) {
	partnerID, req, err := h.read(session, body)
	if err != nil {
		return nil, err
	}
	inForce, err := h.Policies.SetPolicy(ctx, approval.Policy{PartnerID: partnerID, ObjectType: req.ObjectType,
		AllowSinglePerson: req.AllowSinglePerson, ChangedBy: int64(session.Id)})
	if err != nil {
		return nil, err
	}
	return map[string]any{"objectType": req.ObjectType, "allowSinglePerson": req.AllowSinglePerson, "inForce": inForce}, nil
}

// Confirm takes {objectType} and puts the change another administrator set
// in force.
func (h *ApprovalPolicyHandler) Confirm(ctx context.Context, session *model.UserSession, body json.RawMessage) (any, error) {
	partnerID, req, err := h.read(session, body)
	if err != nil {
		return nil, err
	}
	if err := h.Policies.ConfirmPolicy(ctx, partnerID, req.ObjectType, int64(session.Id)); err != nil {
		return nil, err
	}
	return map[string]any{"objectType": req.ObjectType, "inForce": true}, nil
}

func (h *ApprovalPolicyHandler) read(session *model.UserSession, body json.RawMessage) (int64, approvalPolicyChange, error) {
	var req approvalPolicyChange
	partnerID, err := h.SessionPartner(session)
	if err != nil {
		return 0, req, err
	}
	if h.Policies == nil {
		return 0, req, NewAPIError(http.StatusInternalServerError, "approval policy handler not configured")
	}
	if common.DecodeJSON(body, &req) != nil || req.ObjectType == "" {
		return 0, req, NewAPIError(http.StatusBadRequest, "objectType is required")
	}
	return partnerID, req, nil
}
