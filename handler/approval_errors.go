package handler

import (
	"net/http"

	"github.com/nauticana/keel/approval"
)

func init() {
	RegisterErrorMessage(approval.ErrNotFound, http.StatusNotFound, "approval_not_found", "Approval request not found")
	RegisterErrorMessage(approval.ErrInvalidState, http.StatusConflict, "approval_invalid_state", "The approval request is already decided")
	RegisterErrorMessage(approval.ErrAlreadyOpen, http.StatusConflict, "approval_already_open", "The record already has an open approval request")
	RegisterErrorMessage(approval.ErrSameActor, http.StatusForbidden, "approval_same_actor", "The submitter cannot decide this request")
	RegisterErrorMessage(approval.ErrExpired, http.StatusConflict, "approval_expired", "The approval request has expired")
	RegisterErrorMessage(approval.ErrNotMaker, http.StatusForbidden, "approval_not_maker", "Only the submitter can withdraw this request")
}
