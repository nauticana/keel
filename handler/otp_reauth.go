package handler

import (
	"errors"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/user"
)

// GetAuthRoutes returns the signed-in OTP routes.
func (h *OTPHandler) GetAuthRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.RestPrefix + "/user/reauth/send": h.SendReauthOTP,
	}
}

// SendReauthOTP sends the signed-in user a code to present as
// RecentAuth.ReauthCode, so a user with neither a password nor 2FA can still
// re-authenticate. The code goes only to the contact on file.
//
// POST /api/user/reauth/send  { "channel": "email" | "phone" }; empty prefers email.
func (h *OTPHandler) SendReauthOTP(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Channel string `json:"channel"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if h.Cache == nil {
		h.rateLimitUnavailable(w, r, "OTP cache", errors.New("OTPHandler: Cache must be set"))
		return
	}
	account, err := h.UserService.GetUserById(session.Id)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	channel := req.Channel
	if channel == "" {
		channel = otpChannelEmail
		if account.Email == "" {
			channel = otpChannelPhone
		}
	}
	var contact string
	switch channel {
	case otpChannelEmail:
		contact = account.Email
	case otpChannelPhone:
		contact = account.PhoneNumber
	default:
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "channel must be 'phone' or 'email'")
		return
	}
	if contact == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "no "+channel+" on file")
		return
	}
	if err := h.UserService.CheckSignInMethod(session.Id, user.SignInOTP); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	if !h.rateLimitOTP(w, r, contact) {
		return
	}
	otp, err := h.UserService.GenerateOTP(session.Id, user.OTPPurposeReauth)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate OTP")
		return
	}
	if channel == otpChannelEmail {
		h.dispatchOTPEmail(r, session.Id, contact, otp)
	} else {
		h.dispatchOTPSMS(r, session.Id, otp)
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{
		"channel":            channel,
		"resendCountdownSec": config.Config().OTPTTLSeconds,
	})
}
