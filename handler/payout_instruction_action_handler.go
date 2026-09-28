package handler

import (
	"context"
	"fmt"
	"net/http"

	kcommon "github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/payout"
	"github.com/nauticana/keel/port"
)

func init() {
	RegisterErrorMessage(payout.ErrInstructionNotFound, http.StatusNotFound, "payout_instruction_not_found", "Payout instruction not found")
	RegisterErrorMessage(payout.ErrInstructionNotCancellable, http.StatusConflict, "payout_instruction_not_cancellable", "The payout instruction cannot be cancelled in its current state")
	RegisterErrorMessage(payout.ErrInstructionNotRetryable, http.StatusConflict, "payout_instruction_not_retryable", "The payout instruction cannot be retried in its current state")
	RegisterErrorMessage(payout.ErrInstructionNotReviewable, http.StatusConflict, "payout_instruction_not_reviewable", "The payout instruction is not in manual review")
	RegisterErrorMessage(payout.ErrInvalidReviewResolution, http.StatusBadRequest, "invalid_payout_review_resolution", "The resolution is not valid for this payout: check the outcome, note, provider reference and reversed amount")
	RegisterErrorMessage(payout.ErrReversalExceedsLeg, http.StatusBadRequest, "payout_reversal_exceeds_leg", "The reversed amount exceeds the payout amount")
	RegisterErrorMessage(payout.ErrDispatchUnresolved, http.StatusConflict, "payout_dispatch_unresolved", "The payout needs manual reconciliation with the provider")
}

// PayoutInstructionActionHandler serves payout instruction table actions.
// A caller outside a global role acts only on its own partner's instructions.
type PayoutInstructionActionHandler struct {
	AbstractHandler
	DB           port.DatabaseRepository
	Instructions *payout.InstructionService
}

// Routes returns the table-action routes; prefix includes the version segment.
func (h *PayoutInstructionActionHandler) Routes(prefix string) map[string]func(w http.ResponseWriter, r *http.Request) {
	if h.Instructions == nil {
		return map[string]func(w http.ResponseWriter, r *http.Request){}
	}
	return map[string]func(w http.ResponseWriter, r *http.Request){
		TableActionPath(prefix, "payout_instruction", "cancel"): WrapTableAction(h.DB, h.UserService,
			"PAYOUT_INSTRUCTION", "CANCEL", "payout_instruction", h.cancel),
		TableActionPath(prefix, "payout_instruction", "execute"): WrapTableAction(h.DB, h.UserService,
			"PAYOUT_INSTRUCTION", "EXECUTE", "payout_instruction", h.execute),
		TableActionPath(prefix, "payout_instruction", "resolve"): WrapTableAction(h.DB, h.UserService,
			"PAYOUT_INSTRUCTION", "RESOLVE", "payout_instruction", h.resolve),
	}
}

type payoutInstructionActionRequest struct {
	ID int64 `json:"id"`
}

type payoutInstructionResolveRequest struct {
	ID                int64                   `json:"id"`
	Outcome           payout.ReviewResolution `json:"outcome"`
	Note              string                  `json:"note"`
	ProviderReference string                  `json:"provider_reference"`
	ReversedMinor     int64                   `json:"reversed_minor"`
}

func (h *PayoutInstructionActionHandler) cancel(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	instr, ok := h.authorizedInstruction(w, r)
	if !ok {
		return
	}
	if err := h.Instructions.Cancel(r.Context(), instr.ID); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	h.respond(w, r, instr.ID)
}

func (h *PayoutInstructionActionHandler) execute(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	instr, ok := h.authorizedInstruction(w, r)
	if !ok {
		return
	}
	if _, err := h.Instructions.Retry(r.Context(), instr.ID); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	h.respond(w, r, instr.ID)
}

func (h *PayoutInstructionActionHandler) resolve(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req payoutInstructionResolveRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if _, ok := h.authorizeInstruction(w, r, session, req.ID); !ok {
		return
	}
	if _, err := h.Instructions.ResolveReview(r.Context(), req.ID, payout.ReviewResolutionRequest{
		Outcome: req.Outcome, ActorID: int64(session.Id), Note: req.Note,
		ProviderReference: req.ProviderReference, ReversedMinor: req.ReversedMinor,
	}); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	h.respond(w, r, req.ID)
}

func (h *PayoutInstructionActionHandler) authorizedInstruction(w http.ResponseWriter, r *http.Request) (*payout.Instruction, bool) {
	var req payoutInstructionActionRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return nil, false
	}
	return h.authorizeInstruction(w, r, session, req.ID)
}

func (h *PayoutInstructionActionHandler) authorizeInstruction(w http.ResponseWriter, r *http.Request, session *model.UserSession, id int64) (*payout.Instruction, bool) {
	instr, err := h.Instructions.Get(r.Context(), id)
	if err == nil && instr.PartnerID != session.PartnerId && !h.globalRole(r, session) {
		err = fmt.Errorf("%w: %d", payout.ErrInstructionNotFound, id)
	}
	if err != nil {
		h.WriteServiceError(w, r, err)
		return nil, false
	}
	return instr, true
}

func (h *PayoutInstructionActionHandler) globalRole(r *http.Request, session *model.UserSession) bool {
	roles, ok := h.DB.(interface {
		IsGlobalRole(ctx context.Context, userID int) bool
	})
	return ok && roles.IsGlobalRole(r.Context(), session.Id)
}

func (h *PayoutInstructionActionHandler) respond(w http.ResponseWriter, r *http.Request, id int64) {
	instr, err := h.Instructions.Get(r.Context(), id)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	kcommon.WriteJSON(w, http.StatusOK, instr)
}
