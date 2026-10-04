package handler

import (
	"errors"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/oauth/authserver"
	"github.com/nauticana/keel/port"
)

// OAuthSessionCookie carries the AS cookie session minted by a hand-off.
const OAuthSessionCookie = "__Secure-keel_oauth_session"

// HandoffSessionUser is a ready-made OAuthASHandler.ResolveUser that accepts
// the hand-off cookie session; it fails closed on any missing, malformed,
// expired, or unverifiable cookie.
func HandoffSessionUser(handoff *authserver.SessionHandoff, journal logger.ApplicationLogger) func(r *http.Request) *port.UserRef {
	return func(r *http.Request) *port.UserRef {
		if handoff == nil {
			return nil
		}
		c, err := r.Cookie(OAuthSessionCookie)
		if err != nil {
			return nil
		}
		user, err := handoff.Resolve(r.Context(), c.Value)
		if err != nil {
			if journal != nil {
				journal.Error("oauth/as: resolve hand-off session: " + err.Error())
			}
			return nil
		}
		return user
	}
}

func (h *OAuthASHandler) base() *AbstractHandler {
	return &AbstractHandler{UserService: h.UserService, Journal: h.Journal}
}

// mintHandoff is bearer-authenticated, so a cross-site form cannot drive it.
func (h *OAuthASHandler) mintHandoff(w http.ResponseWriter, r *http.Request) {
	base := h.base()
	if !base.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := base.RequireSession(w, r)
	if !ok {
		return
	}
	var req struct {
		Return string `json:"return"`
	}
	if !base.ReadStrictRequest(w, r, &req) {
		return
	}
	grant, err := h.Handoff.Mint(r.Context(), port.UserRef{UserID: int64(session.Id), PartnerID: session.PartnerId}, req.Return)
	switch {
	case errors.Is(err, authserver.ErrHandoffReturn):
		base.WriteRequestError(r, w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	case errors.Is(err, authserver.ErrHandoffUser):
		base.WriteRequestError(r, w, http.StatusUnauthorized, "Unauthorized", err.Error())
		return
	case err != nil:
		base.WriteServiceError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	common.WriteJSON(w, http.StatusOK, map[string]string{"redirect": grant.RedeemURL})
}

// redeemHandoff is a safe GET: the code is single-use and bound to the return URL.
func (h *OAuthASHandler) redeemHandoff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	q := r.URL.Query()
	sess, err := h.Handoff.Redeem(r.Context(), q.Get("code"), q.Get("return"))
	if err != nil {
		if errors.Is(err, authserver.ErrHandoffReturn) || errors.Is(err, authserver.ErrHandoffCode) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if h.Journal != nil {
			h.Journal.Error("oauth/as: redeem hand-off: " + err.Error())
		}
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     OAuthSessionCookie,
		Value:    sess.Token,
		Path:     authserver.OAuthPathPrefix,
		MaxAge:   int(sess.TTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, sess.ReturnURL, http.StatusSeeOther)
}
