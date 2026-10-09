package handler

import (
	"net/http"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

// RecentAuth is the proof a security-sensitive request carries so a stolen
// JWT alone cannot make the change: the current password, a current 2FA code,
// or a code sent by POST /api/user/reauth/send. The first one present is checked.
type RecentAuth struct {
	Password      string `json:"password"`
	TwoFactorCode string `json:"twoFactorCode"`
	ReauthCode    string `json:"reauthCode"`
}

func (h *AbstractHandler) requireRecentAuth(w http.ResponseWriter, r *http.Request, session *model.UserSession, proof RecentAuth) bool {
	var ok bool
	var err error
	switch {
	case proof.Password != "":
		ok, err = h.UserService.VerifyPasswordByID(session.Id, proof.Password)
	case proof.TwoFactorCode != "":
		ok, err = h.UserService.Verify2FA(session.Id, proof.TwoFactorCode)
	case proof.ReauthCode != "":
		// A code proves only what an OTP sign-in would, so it is refused where the SSO policy refuses OTP.
		if err := h.UserService.CheckSignInMethod(session.Id, user.SignInOTP); err != nil {
			h.WriteServiceError(w, r, err)
			return false
		}
		ok = h.UserService.VerifyOTP(session.Id, user.OTPPurposeReauth, proof.ReauthCode) == nil
	default:
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "password, current 2FA code or re-authentication code is required")
		return false
	}
	if err != nil || !ok {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "re-authentication failed")
		return false
	}
	return true
}
