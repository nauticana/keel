package handler

import (
	"net/http"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/user"
)

// ConsentHandler is the authenticated self-service surface for consent: record
// a decision (opt-in or opt-out) against a versioned policy, and export the
// full audit trail. It complements the signup-time recording done inside
// SendOTP / social login — those bundle consents under one signup policy, while
// this front door records any single consent (e.g. terms) under its own policy
// and lets the user export their 10DLC/DSAR history.
//
// Horizontal primitive: every SMS-sending app mounts it. Consent is nil-safe —
// when unset the routes return 503 so an app without a ConsentService builds.
type ConsentHandler struct {
	AbstractHandler
	Consent user.ConsentService
}

func (h *ConsentHandler) GetAuthRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.RestPrefix + "/user/consent": h.ServeConsent,
	}
}

// ServeConsent serves the session user's consent surface: GET exports the audit
// trail, POST records a decision.
func (h *ConsentHandler) ServeConsent(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.History(w, r)
	case http.MethodPost:
		h.Record(w, r)
	default:
		h.WriteError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "use GET or POST")
	}
}

// POST /user/consent — record one consent decision for the session user.
// Body: consentType, consented, policyType, policyVersion, and optional
// policyRegion/policyLanguage/region/eventRef. consented=false is a
// first-class opt-out (the STOP/withdrawal half of the lifecycle).
func (h *ConsentHandler) Record(w http.ResponseWriter, r *http.Request) {
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if h.Consent == nil {
		h.WriteError(w, http.StatusServiceUnavailable, "Unavailable", "consent recording is not configured")
		return
	}
	var req struct {
		ConsentType    string `json:"consentType"`
		Consented      bool   `json:"consented"`
		PolicyType     string `json:"policyType"`
		PolicyVersion  string `json:"policyVersion"`
		PolicyRegion   string `json:"policyRegion"`
		PolicyLanguage string `json:"policyLanguage"`
		Region         string `json:"region"`
		EventRef       string `json:"eventRef"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.ConsentType) == "" || strings.TrimSpace(req.PolicyType) == "" || strings.TrimSpace(req.PolicyVersion) == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "consentType, policyType and policyVersion are required")
		return
	}
	err := h.Consent.Record(r.Context(), user.ConsentRequest{
		UserID:          session.Id,
		Email:           session.Email,
		Phone:           session.PhoneNumber,
		ConsentType:     req.ConsentType,
		Consented:       req.Consented,
		PolicyType:      req.PolicyType,
		PolicyVersion:   req.PolicyVersion,
		PolicyRegion:    req.PolicyRegion,
		PolicyLanguage:  req.PolicyLanguage,
		Region:          req.Region,
		EventRef:        req.EventRef,
		ClientIP:        TrustedClientIP(r),
		ClientUserAgent: r.UserAgent(),
	})
	if err != nil {
		h.WriteError(w, http.StatusFailedDependency, "Consent Not Recorded", err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"recorded": true})
}

// GET /user/consent — the session user's consent audit trail, newest first.
func (h *ConsentHandler) History(w http.ResponseWriter, r *http.Request) {
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if h.Consent == nil {
		h.WriteError(w, http.StatusServiceUnavailable, "Unavailable", "consent recording is not configured")
		return
	}
	events, err := h.Consent.History(r.Context(), user.ConsentSubject{
		UserID: session.Id,
		Email:  session.Email,
		Phone:  session.PhoneNumber,
	})
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Server Error", "could not load consent history")
		return
	}
	items := make([]map[string]any, 0, len(events))
	for _, e := range events {
		items = append(items, map[string]any{
			"consentType":     e.ConsentType,
			"consented":       e.Consented,
			"policyType":      e.PolicyType,
			"policyVersion":   e.PolicyVersion,
			"policyRegion":    e.PolicyRegion,
			"policyLanguage":  e.PolicyLanguage,
			"region":          e.Region,
			"eventRef":        e.EventRef,
			"clientIp":        e.ClientIP,
			"clientUserAgent": e.ClientUserAgent,
			"createdAt":       e.CreatedAt,
		})
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}
