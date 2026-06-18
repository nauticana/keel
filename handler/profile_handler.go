package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

// ProfileHandler is the logged-in user's self-service account surface: edit
// own name/locale (immediate) and change email/phone (verify-before-apply).
// Mount behind the JWT/SSO middleware. When Notify is nil, phone change
// returns 503 rather than a dead-end, so email change can ship without SMS.
type ProfileHandler struct {
	AbstractHandler
	Notify port.NotificationSender
}

func (h *ProfileHandler) GetAuthRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.RestPrefix + "/user/profile":              h.UpdateProfile,
		common.RestPrefix + "/user/profile/email":         h.RequestEmailChange,
		common.RestPrefix + "/user/profile/email/confirm": h.ConfirmEmailChange,
		common.RestPrefix + "/user/profile/phone":         h.RequestPhoneChange,
		common.RestPrefix + "/user/profile/phone/confirm": h.ConfirmPhoneChange,
	}
}

// POST /user/profile  {firstName, lastName, locale}
func (h *ProfileHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	var req struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Locale    string `json:"locale"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.FirstName) == "" {
		h.WriteError(w, http.StatusBadRequest, "Invalid Request", "firstName is required")
		return
	}
	if err := h.UserService.UpdateProfile(session.Id, req.FirstName, req.LastName, req.Locale); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Server Error", "could not update profile")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"message": "Profile updated"})
}

func (h *ProfileHandler) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
	h.requestContactChange(w, r, "email")
}

func (h *ProfileHandler) RequestPhoneChange(w http.ResponseWriter, r *http.Request) {
	h.requestContactChange(w, r, "phone")
}

func (h *ProfileHandler) ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	h.confirmContactChange(w, r, "email")
}

func (h *ProfileHandler) ConfirmPhoneChange(w http.ResponseWriter, r *http.Request) {
	h.confirmContactChange(w, r, "phone")
}

// POST /user/profile/{email,phone}  {value} — code sent to the new value.
func (h *ProfileHandler) requestContactChange(w http.ResponseWriter, r *http.Request, channel string) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	var req struct {
		Value string `json:"value"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	value := strings.TrimSpace(req.Value)
	if value == "" {
		h.WriteError(w, http.StatusBadRequest, "Invalid Request", "value is required")
		return
	}
	if channel == "phone" && h.Notify == nil {
		h.WriteError(w, http.StatusServiceUnavailable, "Unavailable", "phone change is not available yet")
		return
	}
	code, err := h.UserService.CreateContactChange(session.Id, channel, value)
	if err != nil {
		// CreateContactChange's user-facing errors are uniqueness conflicts.
		h.WriteError(w, http.StatusConflict, "Conflict", err.Error())
		return
	}
	body := fmt.Sprintf("Your confirmation code is %d. It expires in 15 minutes.", code)
	var sendErr error
	if channel == "phone" {
		sendErr = h.Notify.SendSMS(r.Context(), value, body)
	} else if h.Notify != nil {
		sendErr = h.Notify.SendEmail(r.Context(), value, "Confirm your new email", body)
	} else {
		sendErr = fmt.Errorf("no notification sender configured")
	}
	if sendErr != nil {
		h.WriteError(w, http.StatusServiceUnavailable, "Unavailable", "could not send the confirmation code")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"message": "Confirmation code sent"})
}

// POST /user/profile/{email,phone}/confirm  {value, code}
func (h *ProfileHandler) confirmContactChange(w http.ResponseWriter, r *http.Request, channel string) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	var req struct {
		Value string `json:"value"`
		Code  int    `json:"code"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Value) == "" || req.Code == 0 {
		h.WriteError(w, http.StatusBadRequest, "Invalid Request", "value and code are required")
		return
	}
	if err := h.UserService.ConfirmContactChange(session.Id, channel, req.Value, req.Code); err != nil {
		h.WriteError(w, http.StatusBadRequest, "Invalid Confirmation", "invalid or expired confirmation")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"message": "Updated"})
}
