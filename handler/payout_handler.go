package handler

import (
	"io"
	"net/http"
	"strings"

	kcommon "github.com/nauticana/keel/common"
	"github.com/nauticana/keel/payout"
)

// PayoutHandler bridges HTTP to payout.OnboardingService. The two
// endpoint families have very different auth shapes:
//
//   - /api/v1/payout/* — authenticated user session, scoped to the
//     caller's (user_id, partner_id).
//   - /api/v1/webhook/payout/{code} — unauthenticated but signature-
//     verified inside the provider impl.
//
// Downstream applications mount these routes against their own router
// — call Routes(prefix) for a map[path]handler the standard library
// http.ServeMux will accept, or invoke the methods directly to mount
// each one yourself.
type PayoutHandler struct {
	AbstractHandler
	PayoutService *payout.OnboardingService
}

// Routes returns the path → handler map for both onboarding and
// webhook endpoints. Mount under your application's REST prefix
// (typically "/api/v1"). All three configured provider webhook paths
// are pre-registered — non-active codes 401 inside the service when
// the signature header doesn't match the configured provider.
func (h *PayoutHandler) Routes(prefix string) map[string]func(w http.ResponseWriter, r *http.Request) {
	if h.PayoutService == nil {
		return map[string]func(w http.ResponseWriter, r *http.Request){}
	}
	return map[string]func(w http.ResponseWriter, r *http.Request){
		prefix + "/payout/onboard/start":   h.StartOnboarding,
		prefix + "/payout/reusable":        h.ListReusable,
		prefix + "/payout/reusable/link":   h.LinkReusable,
		prefix + "/payout/status":          h.Status,
		prefix + "/webhook/payout/AW":      h.Webhook,
		prefix + "/webhook/payout/SC":      h.Webhook,
		prefix + "/webhook/payout/WI":      h.Webhook,
	}
}

// StartOnboarding returns a URL the calling application opens
// (webview or external browser) to step through the provider's hosted
// KYC. The session's partner_id scopes which user_bank_info row gets
// back-filled — multi-partner users run this once per partner unless
// they reuse an existing account via LinkReusable.
func (h *PayoutHandler) StartOnboarding(w http.ResponseWriter, r *http.Request) {
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	out, err := h.PayoutService.StartOnboarding(r.Context(), session.Id, session.PartnerId)
	if err != nil {
		h.WriteError(w, http.StatusConflict, "Conflict", err.Error())
		return
	}
	kcommon.WriteJSON(w, http.StatusOK, out)
}

// ListReusable returns provider accounts the user already has on
// OTHER partners and could reuse for the current partner.
func (h *PayoutHandler) ListReusable(w http.ResponseWriter, r *http.Request) {
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	accounts, err := h.PayoutService.ListReusableAccounts(r.Context(), session.Id, session.PartnerId)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	kcommon.WriteJSON(w, http.StatusOK, map[string]any{"accounts": accounts})
}

type linkReusableRequest struct {
	ProviderAccountID string `json:"providerAccountId"`
}

// LinkReusable copies an existing provider_account_id from one of the
// user's other-partner rows onto the calling partner's row. No
// provider API call — the account is already cleared on the provider
// side, this is bookkeeping inside the application.
func (h *PayoutHandler) LinkReusable(w http.ResponseWriter, r *http.Request) {
	var req linkReusableRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if err := h.PayoutService.LinkReusableAccount(r.Context(), session.Id, session.PartnerId, req.ProviderAccountID); err != nil {
		h.WriteError(w, http.StatusConflict, "Conflict", err.Error())
		return
	}
	kcommon.WriteJSON(w, http.StatusOK, map[string]string{"message": "account linked"})
}

// Status reports whether the calling user has a populated
// provider_account_id on the active partner row. Drives the calling
// application's "complete bank onboarding" banner.
func (h *PayoutHandler) Status(w http.ResponseWriter, r *http.Request) {
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	complete, err := h.PayoutService.IsOnboardingComplete(r.Context(), session.Id, session.PartnerId)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	kcommon.WriteJSON(w, http.StatusOK, map[string]any{"complete": complete})
}

// Webhook is the provider-facing endpoint. NOT authenticated — caller
// is the provider's webhook poster, not a logged-in user. Signature
// verification happens inside the provider impl. The path is
// {prefix}/webhook/payout/{providerCode}; providerCode is parsed off
// the last URL segment.
//
// Returns 200 OK on acceptance. On signature failure, replies 401 so
// the provider retries with exponential backoff (matches every major
// provider's convention).
func (h *PayoutHandler) Webhook(w http.ResponseWriter, r *http.Request) {
	providerCode := extractProviderCode(r.URL.Path)
	if providerCode == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "missing provider code in path")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "read body: "+err.Error())
		return
	}
	if err := h.PayoutService.HandleWebhook(r.Context(), providerCode, r.Header, body); err != nil {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", err.Error())
		return
	}
	kcommon.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// extractProviderCode pulls the last path segment off the webhook URL.
// e.g. "/api/v1/webhook/payout/AW" → "AW".
func extractProviderCode(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx < 0 || idx == len(path)-1 {
		return ""
	}
	return path[idx+1:]
}
