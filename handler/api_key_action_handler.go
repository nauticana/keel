package handler

import (
	"errors"
	"net/http"

	kcommon "github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/service"
)

// APIKeyActionHandler exposes the custom table-actions for the basis api_key
// table — generate, roll and restrict. List and Delete (revoke) are served by
// keel's generic UserSpecific REST CRUD; only key minting needs custom logic
// (a random key + sha256 hash, with the plaintext shown exactly once).
//
// Registered via the table_action framework (table_action rows +
// API_KEY/GENERATE, ROLL and RESTRICT authorization) at the conventional URLs
// POST /<prefix>/api_key/{generate,roll,restrict} — so the buttons
// auto-render in sail's generic CRUD views and the auth gate flows through
// WrapTableAction.
type APIKeyActionHandler struct {
	AbstractHandler
	DB   port.DatabaseRepository
	Keys *service.APIKeyService
}

// Routes returns the table-action routes. prefix is the REST prefix
// INCLUDING the version segment (typically "/api/v1").
func (h *APIKeyActionHandler) Routes(prefix string) map[string]func(w http.ResponseWriter, r *http.Request) {
	if h.Keys == nil {
		return map[string]func(w http.ResponseWriter, r *http.Request){}
	}
	return map[string]func(w http.ResponseWriter, r *http.Request){
		TableActionPath(prefix, "api_key", "generate"): WrapTableAction(h.DB, h.UserService,
			"API_KEY", "GENERATE", "api_key", h.generate),
		TableActionPath(prefix, "api_key", "roll"): WrapTableAction(h.DB, h.UserService,
			"API_KEY", "ROLL", "api_key", h.roll),
		TableActionPath(prefix, "api_key", "restrict"): WrapTableAction(h.DB, h.UserService,
			"API_KEY", "RESTRICT", "api_key", h.restrict),
	}
}

type generateKeyRequest struct {
	KeyName      string `json:"key_name"`
	Scopes       string `json:"scopes"`
	AllowedCIDRs string `json:"allowed_cidrs"`
}

// generate mints a new key owned by (session partner, session user) and returns
// the plaintext once. Table-level action — no row id.
func (h *APIKeyActionHandler) generate(w http.ResponseWriter, r *http.Request) {
	var req generateKeyRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if req.KeyName == "" {
		req.KeyName = "default"
	}
	if req.Scopes == "" {
		req.Scopes = "query"
	}
	key, prefix, err := h.Keys.InsertKey(r.Context(), session.PartnerId, int64(session.Id), req.KeyName, req.Scopes, req.AllowedCIDRs)
	switch {
	case errors.Is(err, service.ErrInvalidScopes), errors.Is(err, kcommon.ErrInvalidCIDRList):
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	case errors.Is(err, service.ErrAPIKeyLimit):
		h.WriteError(w, http.StatusConflict, "Conflict", err.Error())
		return
	case err != nil:
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	kcommon.WriteJSON(w, http.StatusCreated, map[string]string{"api_key": key, "key_prefix": prefix})
}

type rollKeyRequest struct {
	ID int64 `json:"id"`
}

// roll rotates the selected key (row-level action): the old key keeps a 24h
// grace window, and a fresh key with the same name/scopes/ownership is returned
// (plaintext once).
func (h *APIKeyActionHandler) roll(w http.ResponseWriter, r *http.Request) {
	var req rollKeyRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	key, prefix, err := h.Keys.RotateKey(r.Context(), req.ID, session.PartnerId)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	if key == "" {
		h.WriteError(w, http.StatusNotFound, "Not Found", "key not found or already inactive")
		return
	}
	kcommon.WriteJSON(w, http.StatusOK, map[string]string{"api_key": key, "key_prefix": prefix})
}

type restrictKeyRequest struct {
	ID           int64  `json:"id"`
	AllowedCIDRs string `json:"allowed_cidrs"`
}

// restrict replaces the networks the selected key may be used from (row-level
// action); an empty list allows any address.
func (h *APIKeyActionHandler) restrict(w http.ResponseWriter, r *http.Request) {
	var req restrictKeyRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	found, err := h.Keys.RestrictKey(r.Context(), req.ID, session.PartnerId, req.AllowedCIDRs)
	switch {
	case errors.Is(err, kcommon.ErrInvalidCIDRList):
		h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
	case err != nil:
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
	case !found:
		h.WriteError(w, http.StatusNotFound, "Not Found", "key not found or already inactive")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
