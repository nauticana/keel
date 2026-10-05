package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

const (
	handoffPurpose    = "signin_handoff"
	handoffTTLSeconds = 300
)

func init() {
	RegisterErrorCode(user.ErrInvalidConfirmation, http.StatusBadRequest, "invalid_confirmation")
	RegisterErrorCode(user.ErrPublicEmail, http.StatusBadRequest, "business_email_required")
	RegisterErrorMessage(user.ErrDuplicateEmail, http.StatusConflict, "email_taken", "an account already exists for this email")
	RegisterErrorCode(user.ErrAlreadyMember, http.StatusConflict, "already_member")
	RegisterErrorCode(user.ErrAccountExists, http.StatusConflict, "account_exists")
}

// GetAuthRoutes returns the signed-in registration routes under apiPrefix.
func (h *PublicHandler) GetAuthRoutes(apiPrefix string) map[string]func(w http.ResponseWriter, r *http.Request) {
	routes := map[string]func(w http.ResponseWriter, r *http.Request){}
	if h.RegisterService != nil {
		routes[apiPrefix+"/register/partner"] = h.CreatePartner
	}
	return routes
}

// CreatePartner creates the partner of a signed-in user who has none, from a
// user.PartnerSetup body. The client refreshes its token to pick up the partner.
func (h *PublicHandler) CreatePartner(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req user.PartnerSetup
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	created, err := h.RegisterService.CreatePartner(r.Context(), int64(session.Id), &req, nil)
	if !h.checkoutTolerated(w, r, err) {
		return
	}
	common.WriteJSON(w, http.StatusOK, created)
}

// checkoutTolerated writes err unless it is only a failed checkout, which
// leaves the registration complete and is logged.
func (h *PublicHandler) checkoutTolerated(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return true
	}
	if !errors.Is(err, user.ErrCheckout) {
		h.WriteServiceError(w, r, err)
		return false
	}
	if h.Journal != nil {
		h.Journal.Error(fmt.Sprintf("registration %s: %v", r.URL.Path, err))
	}
	return true
}

type handoffGrant struct {
	UserID       int    `json:"userId"`
	SignInMethod string `json:"signInMethod"`
}

// HandoffCode stores a completed sign-in under a single-use code, for a
// redirect that must not carry tokens. The client trades it at
// /public/register/exchange within five minutes.
func (h *PublicHandler) HandoffCode(ctx context.Context, session *model.UserSession) (string, error) {
	if h.Handoff == nil {
		return "", errors.New("handoff: no nonce service")
	}
	if session == nil || session.Id <= 0 || session.SignInMethod == "" {
		return "", errors.New("handoff: a signed-in session is required")
	}
	grant, err := json.Marshal(handoffGrant{UserID: session.Id, SignInMethod: session.SignInMethod})
	if err != nil {
		return "", err
	}
	return h.Handoff.Create(ctx, handoffPurpose, string(grant))
}

// ExchangeHandoff trades a HandoffCode for tokens. The account and sign-in
// policy are checked again, and an untrusted device with 2FA gets a login
// token as at password login.
func (h *PublicHandler) ExchangeHandoff(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !h.ReadStrictRequest(w, r, &req) || !h.RequireFields(w, map[string]string{"code": req.Code}) {
		return
	}
	payload, ok, err := h.Handoff.Consume(r.Context(), req.Code, handoffPurpose, handoffTTLSeconds)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	var grant handoffGrant
	if !ok || json.Unmarshal([]byte(payload), &grant) != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid or expired code")
		return
	}
	session, err := h.UserService.GetUserById(grant.UserID)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	if err := h.UserService.CheckSignInMethod(session.Id, grant.SignInMethod); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	session.SignInMethod = grant.SignInMethod
	if h.secondFactorPending(w, r, session) {
		return
	}
	resp, err := h.SessionTokens(session)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	resp["twoFactorRequired"] = false
	common.WriteJSON(w, http.StatusOK, resp)
}
