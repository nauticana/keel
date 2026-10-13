package handler

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	kcommon "github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/service"
)

func init() {
	RegisterErrorCode(service.ErrInvalidScopes, http.StatusBadRequest, "api_key_scopes")
	RegisterErrorCode(service.ErrInvalidAPIKey, http.StatusBadRequest, "api_key_invalid")
	RegisterErrorCode(service.ErrAPIKeyLimit, http.StatusConflict, "api_key_limit")
}

// APIKeyActionHandler exposes generate, roll and restrict table actions.
type APIKeyActionHandler struct {
	AbstractHandler
	DB   port.DatabaseRepository
	Keys *service.APIKeyService
}

// Routes returns table-action routes under a versioned REST prefix.
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
	ExpiresAt    string `json:"expires_at"`
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
	var expiresAt time.Time
	if text := strings.TrimSpace(req.ExpiresAt); text != "" {
		var err error
		expiresAt, err = time.Parse(time.RFC3339, text)
		if err != nil {
			h.WriteServiceError(w, r, fmt.Errorf("%w: expiry must be RFC 3339", service.ErrInvalidAPIKey))
			return
		}
	}
	key, prefix, err := h.Keys.InsertKey(r.Context(), service.NewAPIKey{
		PartnerID: session.PartnerId, UserID: int64(session.Id), Name: req.KeyName,
		Scopes: req.Scopes, AllowedCIDRs: req.AllowedCIDRs, ExpiresAt: expiresAt,
	})
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	kcommon.WriteJSON(w, http.StatusCreated, map[string]string{"api_key": key, "key_prefix": prefix})
}

type rollKeyRequest struct {
	ID int64 `json:"id"`
}

func (h *APIKeyActionHandler) roll(w http.ResponseWriter, r *http.Request) {
	var req rollKeyRequest
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	key, prefix, err := h.Keys.RotateKey(r.Context(), req.ID, session.PartnerId)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	if key == "" {
		h.WriteError(w, http.StatusNotFound, "Not Found", "key not found, inactive or expired")
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
	case err != nil:
		h.WriteServiceError(w, r, err)
	case !found:
		h.WriteError(w, http.StatusNotFound, "Not Found", "key not found or already inactive")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
