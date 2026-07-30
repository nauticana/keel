package handler

import (
	"net/http"
	"net/url"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

func init() {
	RegisterErrorStatus(port.ErrAgencyNotFound, http.StatusNotFound)
	RegisterErrorStatus(port.ErrNotClientOwner, http.StatusForbidden)
	RegisterErrorStatus(port.ErrDelegationExists, http.StatusConflict)
	RegisterErrorStatus(port.ErrSelfDelegation, http.StatusConflict)
	RegisterErrorStatus(port.ErrAgencyNotApproved, http.StatusForbidden)
	RegisterErrorStatus(port.ErrAgencySuspended, http.StatusForbidden)
	RegisterErrorStatus(port.ErrNoPartnerYet, http.StatusConflict)
	RegisterErrorStatus(port.ErrInviteExpired, http.StatusGone)
	RegisterErrorStatus(port.ErrInvalidBillingModel, http.StatusUnprocessableEntity)
	RegisterErrorStatus(port.ErrWholesaleNotAllowed, http.StatusForbidden)
	RegisterErrorStatus(port.ErrCommissionRateAbsent, http.StatusConflict)
	RegisterErrorStatus(port.ErrInvalidCommission, http.StatusUnprocessableEntity)
	RegisterErrorStatus(port.ErrPayoutDestination, http.StatusConflict)
}

// AgencyHandler is the HTTP bridge for keel/agency. InviteURL turns a token
// into the consuming application's accept-page URL; when nil, a relative
// /agency/accept URL is returned.
type AgencyHandler struct {
	AbstractHandler
	DB        port.DatabaseRepository
	Agency    port.AgencyService
	InviteURL func(token string) string
}

// Routes returns the public invite-info endpoint, authenticated agency
// endpoints, and the agency_profile approve table action. apiPrefix normally
// includes the version ("/api/v1"); publicPrefix is normally "/public".
func (h *AgencyHandler) Routes(apiPrefix, publicPrefix string) map[string]func(http.ResponseWriter, *http.Request) {
	if h.Agency == nil {
		return map[string]func(http.ResponseWriter, *http.Request){}
	}
	manage := func(inner http.HandlerFunc) http.HandlerFunc {
		return WrapTableAction(h.DB, h.UserService, "AGENCY", "MANAGE_CLIENTS", "agency_clients", inner)
	}
	earnings := WrapTableAction(h.DB, h.UserService, "AGENCY", "VIEW_EARNINGS", "agency_earnings", h.Earnings)
	viewPayoutProfile := WrapTableAction(h.DB, h.UserService, "AGENCY", "VIEW_EARNINGS", "agency_earnings", h.PayoutProfile)
	managePayoutProfile := WrapTableAction(h.DB, h.UserService, "AGENCY", "MANAGE_PAYOUT", "agency_payout_profile", h.PayoutProfile)
	payoutProfile := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			managePayoutProfile(w, r)
			return
		}
		viewPayoutProfile(w, r)
	}
	return map[string]func(http.ResponseWriter, *http.Request){
		publicPrefix + "/agency/invite":         h.InviteInfo,
		apiPrefix + "/agency/enroll":            h.Enroll,
		apiPrefix + "/agency/profile":           h.Profile,
		apiPrefix + "/agency/clients":           manage(h.Clients),
		apiPrefix + "/agency/clients/invite":    manage(h.InviteClient),
		apiPrefix + "/agency/clients/cancel":    manage(h.CancelClient),
		apiPrefix + "/agency/billing-model":     manage(h.SetBillingModel),
		apiPrefix + "/agency/earnings":          earnings,
		apiPrefix + "/agency/payout-profile":    payoutProfile,
		apiPrefix + "/agency/invite/accept":     h.AcceptInvite,
		apiPrefix + "/agency/delegation":        h.Delegation,
		apiPrefix + "/agency/delegation/revoke": h.RevokeDelegation,
		TableActionPath(apiPrefix, "agency_profile", "approve"): WrapTableAction(
			h.DB, h.UserService, "AGENCY_PROFILE", "APPROVE", "agency_profile", h.approve),
	}
}

func (h *AgencyHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if session.PartnerId <= 0 {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "No partner associated with session")
		return
	}
	if err := h.Agency.Enroll(r.Context(), session.PartnerId, int64(session.Id)); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"message": "agency application received"})
}

func (h *AgencyHandler) Profile(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	partnerID, ok := h.RequirePartner(w, r)
	if !ok {
		return
	}
	profile, err := h.Agency.Profile(r.Context(), partnerID)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"profile": profile})
}

func (h *AgencyHandler) Clients(w http.ResponseWriter, r *http.Request) {
	partnerID, ok := h.RequirePartner(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		clients, err := h.Agency.ListClients(r.Context(), partnerID)
		if err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
		active, err := h.Agency.CountActiveDelegations(r.Context(), partnerID)
		if err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
		common.WriteJSON(w, http.StatusOK, map[string]any{"items": clients, "activeClients": active})
	case http.MethodPost:
		var request struct {
			Clients []port.AgencyClientInput `json:"clients"`
		}
		if !h.ReadRequest(w, r, &request) {
			return
		}
		if len(request.Clients) == 0 || len(request.Clients) > 1000 {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "Supply 1 to 1000 clients")
			return
		}
		added, err := h.Agency.AddClients(r.Context(), partnerID, request.Clients)
		if err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
		common.WriteJSON(w, http.StatusOK, map[string]int{"added": added})
	default:
		h.WriteError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "Use GET or POST")
	}
}

func (h *AgencyHandler) InviteClient(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	partnerID, ok := h.RequirePartner(w, r)
	if !ok {
		return
	}
	var request struct {
		InvitationID int64 `json:"invitationId"`
	}
	if !h.ReadRequest(w, r, &request) {
		return
	}
	token, err := h.Agency.Invite(r.Context(), partnerID, request.InvitationID)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	inviteURL := "/agency/accept?token=" + url.QueryEscape(token)
	if h.InviteURL != nil {
		inviteURL = h.InviteURL(token)
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"inviteLink": inviteURL})
}

func (h *AgencyHandler) CancelClient(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	partnerID, ok := h.RequirePartner(w, r)
	if !ok {
		return
	}
	var request struct {
		InvitationID int64 `json:"invitationId"`
	}
	if !h.ReadRequest(w, r, &request) {
		return
	}
	if err := h.Agency.CancelClient(r.Context(), partnerID, request.InvitationID); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (h *AgencyHandler) InviteInfo(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	invite, err := h.Agency.InviteInfo(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, invite)
}

func (h *AgencyHandler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	session, ok := h.ReadAuthRequest(w, r, &request)
	if !ok {
		return
	}
	if err := h.Agency.AcceptInvite(r.Context(), request.Token, int64(session.Id), session.PartnerId); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

func (h *AgencyHandler) Delegation(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	partnerID, ok := h.RequirePartner(w, r)
	if !ok {
		return
	}
	delegation, err := h.Agency.ClientDelegation(r.Context(), partnerID)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"delegation": delegation})
}

func (h *AgencyHandler) RevokeDelegation(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		ClientPartnerID int64 `json:"clientPartnerId"`
	}
	session, ok := h.ReadAuthRequest(w, r, &request)
	if !ok {
		return
	}
	if request.ClientPartnerID == 0 {
		request.ClientPartnerID = session.PartnerId
	}
	if err := h.Agency.RevokeDelegation(r.Context(), request.ClientPartnerID, session.PartnerId, int64(session.Id)); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (h *AgencyHandler) SetBillingModel(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	partnerID, ok := h.RequirePartner(w, r)
	if !ok {
		return
	}
	var request struct {
		ClientPartnerID int64  `json:"clientPartnerId"`
		BillingModel    string `json:"billingModel"`
	}
	if !h.ReadRequest(w, r, &request) {
		return
	}
	if err := h.Agency.SetBillingModel(r.Context(), partnerID, request.ClientPartnerID, request.BillingModel); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"billingModel": request.BillingModel})
}

func (h *AgencyHandler) Earnings(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	partnerID, ok := h.RequirePartner(w, r)
	if !ok {
		return
	}
	earnings, err := h.Agency.Earnings(r.Context(), partnerID)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, earnings)
}

func (h *AgencyHandler) PayoutProfile(w http.ResponseWriter, r *http.Request) {
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if session.PartnerId <= 0 {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "No partner associated with session")
		return
	}
	switch r.Method {
	case http.MethodGet:
		profile, destinations, err := h.Agency.PayoutProfile(r.Context(), session.PartnerId, int64(session.Id))
		if err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
		common.WriteJSON(w, http.StatusOK, map[string]any{
			"profile": profile, "destinations": destinations,
		})
	case http.MethodPost:
		var request struct {
			UserBankInfoID int64 `json:"userBankInfoId"`
		}
		if !h.ReadRequest(w, r, &request) {
			return
		}
		if err := h.Agency.SetPayoutProfile(r.Context(), session.PartnerId, int64(session.Id), request.UserBankInfoID); err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
		common.WriteJSON(w, http.StatusOK, map[string]string{"status": "active"})
	default:
		h.WriteError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "Use GET or POST")
	}
}

func (h *AgencyHandler) approve(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		ID int64 `json:"id"`
	}
	if _, ok := h.ReadAuthRequest(w, r, &request); !ok {
		return
	}
	if err := h.Agency.Approve(r.Context(), request.ID); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}
