package handler

import (
	"context"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

func init() {
	RegisterErrorCode(domain.ErrDomainNotFound, http.StatusNotFound, "domain_not_found")
	RegisterErrorCode(domain.ErrInvalidDomain, http.StatusUnprocessableEntity, "domain_not_verifiable")
	RegisterErrorCode(domain.ErrUnknownMethod, http.StatusUnprocessableEntity, "domain_method_unsupported")
	RegisterErrorCode(domain.ErrNotMember, http.StatusForbidden, "domain_not_member")
	RegisterErrorCode(domain.ErrDomainHeld, http.StatusConflict, "domain_held")
	RegisterErrorCode(domain.ErrNoChallenge, http.StatusConflict, "domain_no_challenge")
	RegisterErrorCode(domain.ErrTooManyTries, http.StatusTooManyRequests, "domain_too_many_tries")
	RegisterErrorCode(domain.ErrCooldown, http.StatusTooManyRequests, "domain_challenge_cooldown")
	RegisterErrorCode(domain.ErrRecipient, http.StatusUnprocessableEntity, "domain_recipient")
	RegisterErrorCode(domain.ErrNoVerification, http.StatusNotFound, "domain_no_verification")
	RegisterErrorCode(domain.ErrDomainNotProven, http.StatusUnprocessableEntity, "domain_not_proven")
}

// DomainVerificationHandler is the HTTP bridge for challenge-based domain
// verification (EC, DT, HF) and cancellation. Methods that need a verified
// identity or a provider grant are called on the service by the flow that
// holds them. History is read through the generic partner_domain REST child.
type DomainVerificationHandler struct {
	AbstractHandler
	DB      port.DatabaseRepository
	Domains *domain.Service
	// SendCode delivers an email code (EC) to recipient. Nil refuses EC.
	SendCode func(ctx context.Context, recipient, domainName, code string) error
}

// Routes mounts challenge, confirm and cancel under apiPrefix, each gated by
// the PARTNER_DOMAIN grant.
func (h *DomainVerificationHandler) Routes(apiPrefix string) map[string]func(http.ResponseWriter, *http.Request) {
	verify := func(inner http.HandlerFunc) http.HandlerFunc {
		return WrapTableAction(h.DB, h.UserService, "PARTNER_DOMAIN", "VERIFY", "partner_domain", inner)
	}
	return map[string]func(http.ResponseWriter, *http.Request){
		TableActionPath(apiPrefix, "partner_domain", "challenge"): verify(h.Challenge),
		TableActionPath(apiPrefix, "partner_domain", "confirm"):   verify(h.Confirm),
		TableActionPath(apiPrefix, "partner_domain", "unverify"): WrapTableAction(
			h.DB, h.UserService, "PARTNER_DOMAIN", "CANCEL", "partner_domain", h.Cancel),
	}
}

type domainVerificationRequest struct {
	DomainURL string `json:"domainUrl"`
	Method    string `json:"method"`
	Recipient string `json:"recipient,omitempty"`
	Code      string `json:"code,omitempty"`
}

// Challenge issues a challenge. DNS and HTTP challenges return what to
// publish; an email code is sent and never returned.
func (h *DomainVerificationHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	session, req, ok := h.read(w, r)
	if !ok {
		return
	}
	if req.Method == domain.MethodEmailCode && h.SendCode == nil {
		h.WriteServiceError(w, r, domain.ErrUnknownMethod)
		return
	}
	ch, err := h.Domains.Challenge(r.Context(), session.PartnerId, int64(session.Id), req.DomainURL, req.Method, req.Recipient)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	if ch.Method == domain.MethodEmailCode {
		if err := h.SendCode(r.Context(), ch.Recipient, ch.DomainName, ch.Token); err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"challenge": ch})
}

// Confirm checks the open challenge and records the verification.
func (h *DomainVerificationHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	session, req, ok := h.read(w, r)
	if !ok {
		return
	}
	v, err := h.Domains.Confirm(r.Context(), session.PartnerId, int64(session.Id), req.DomainURL, req.Method, req.Code)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"verification": v})
}

// Cancel withdraws current evidence by method, or by every method when empty.
func (h *DomainVerificationHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	session, req, ok := h.read(w, r)
	if !ok {
		return
	}
	methods, err := h.Domains.Cancel(r.Context(), session.PartnerId, int64(session.Id), req.DomainURL, req.Method)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"cancelled": methods})
}

func (h *DomainVerificationHandler) read(w http.ResponseWriter, r *http.Request) (session *model.UserSession, req domainVerificationRequest, ok bool) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return nil, req, false
	}
	if h.Domains == nil {
		h.WriteError(w, http.StatusServiceUnavailable, "Unavailable", "domain verification is not configured")
		return nil, req, false
	}
	session, ok = h.ReadAuthRequest(w, r, &req)
	if !ok {
		return nil, req, false
	}
	if session.PartnerId <= 0 {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "No partner associated with session")
		return nil, req, false
	}
	if !h.RequireFields(w, map[string]string{"domainUrl": req.DomainURL}) {
		return nil, req, false
	}
	return session, req, true
}
