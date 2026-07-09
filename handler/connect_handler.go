package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/oauth/client"
	"github.com/nauticana/keel/oauth/connect"
)

// parseEntity validates an optional entity_id: empty → 0 (tenant-wide), else a
// non-negative int. A malformed value errors rather than silently scoping to 0.
func parseEntity(v string) (int64, error) {
	if v == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id < 0 {
		return 0, fmt.Errorf("invalid entity_id %q", v)
	}
	return id, nil
}

// callbackValidator is an optional provider capability: validate the raw callback
// query (e.g. Shopify HMAC + shop host) before the token exchange. Providers that
// don't implement it skip the check.
type callbackValidator interface {
	ValidateCallback(ctx context.Context, query url.Values) error
}

// OAuthConnectHandler is the thin HTTP layer for partner→provider OAuth
// connections: it delegates to client.Provider implementations and handles only
// HTTP concerns (params, responses, the browser redirect). Mount its Routes().
type OAuthConnectHandler struct {
	AbstractHandler
	Providers map[string]client.Provider
	// FrontendReturnURL is where the callback redirects the browser after a
	// connection completes; the result is appended as "?<provider>=success".
	FrontendReturnURL string
	// Store, when set, enables POST /api/oauth/apikey for non-OAuth providers,
	// sealing the supplied key at rest. Leave nil for OAuth-only apps.
	Store connect.Store
	// Authz gates the connection-mutating routes (authorize / test / apikey) —
	// e.g. WrapTableAction(db, userSvc, "PARTNER_CREDENTIAL", "MANAGE", scope,
	// inner). The provider callback is left ungated (reached by a provider redirect,
	// proven by the single-use OAuth state). Required unless AllowAnyPartner is set:
	// with neither, the gated routes fail closed (403).
	Authz func(http.HandlerFunc) http.HandlerFunc
	// AllowAnyPartner opts out of Authz, letting any authenticated partner user
	// manage connections. Only for single-role apps that intend it.
	AllowAnyPartner bool
}

// Routes returns the authorize/callback/test endpoints for every registered
// provider, keyed by path, for the app to mount.
func (h *OAuthConnectHandler) Routes() map[string]http.HandlerFunc {
	routes := make(map[string]http.HandlerFunc, len(h.Providers)*3)
	for name, p := range h.Providers {
		name, p := name, p
		routes["/api/oauth/"+name+"/authorize"] = h.gate(h.authorize(name, p))
		routes["/api/oauth/"+name+"/callback"] = h.callback(name, p)
		routes["/api/oauth/"+name+"/test"] = h.gate(h.test(name, p))
	}
	if h.Store != nil {
		routes["/api/oauth/apikey"] = h.gate(h.saveAPIKey)
	}
	return routes
}

// gate applies the Authz middleware to a mutating route, or fails closed when
// neither Authz nor AllowAnyPartner is configured.
func (h *OAuthConnectHandler) gate(inner http.HandlerFunc) http.HandlerFunc {
	if h.Authz != nil {
		return h.Authz(inner)
	}
	if h.AllowAnyPartner {
		return inner
	}
	return func(w http.ResponseWriter, r *http.Request) {
		h.WriteError(w, http.StatusForbidden, "Forbidden", "connection management authorization not configured")
	}
}

// apiKeyRequest is the body for POST /api/oauth/apikey (non-OAuth providers).
type apiKeyRequest struct {
	Provider    string `json:"provider"`
	CredRef     string `json:"cred_ref"`
	APIEndpoint string `json:"api_endpoint"`
	EntityID    int64  `json:"entity_id"`
}

// saveAPIKey stores an API-key connection, sealing the key at rest via the Store
// (the generic REST path would persist it in the clear).
func (h *OAuthConnectHandler) saveAPIKey(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	partnerID, ok := h.RequirePartner(w, r)
	if !ok {
		return
	}
	var req apiKeyRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // cap the credential body at 64 KiB
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Provider == "" || req.CredRef == "" || req.EntityID < 0 {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "provider and cred_ref are required")
		return
	}
	// An OAuth provider must not be replaceable via the API-key path (that would
	// overwrite its OAuth connection with an attacker-supplied key).
	if _, isOAuth := h.Providers[req.Provider]; isOAuth {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "provider "+req.Provider+" uses OAuth, not an API key")
		return
	}
	ctx := client.WithEntity(r.Context(), req.EntityID)
	if err := h.Store.UpsertConnection(ctx, partnerID, req.Provider, client.ConnTypeAPIKey, req.CredRef, req.APIEndpoint); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Save Failed", err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// authorize returns the provider consent URL. Query params (e.g. shop for
// Shopify, entity_id for per-business scoping) ride the OAuth state across the
// redirect.
func (h *OAuthConnectHandler) authorize(_ string, p client.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.RequireMethod(w, r, http.MethodGet) {
			return
		}
		partnerID, ok := h.RequirePartner(w, r)
		if !ok {
			return
		}
		params := make(map[string]string)
		for k, v := range r.URL.Query() {
			if len(v) > 0 {
				params[k] = v[0]
			}
		}
		entityID, err := parseEntity(params[client.StateEntityKey])
		if err != nil {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
			return
		}
		params[client.StateEntityKey] = strconv.FormatInt(entityID, 10)
		u, err := p.AuthURL(r.Context(), partnerID, params)
		if err != nil {
			h.WriteError(w, http.StatusInternalServerError, "OAuth URL Generation Failed", err.Error())
			return
		}
		common.WriteJSON(w, http.StatusOK, map[string]string{"url": u})
	}
}

// callback finishes the flow. Browser-redirect: failures redirect/return an error
// rather than a JSON envelope. The entity scope is recovered from the state by
// the provider, not the handler.
func (h *OAuthConnectHandler) callback(name string, p client.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.RequireMethod(w, r, http.MethodGet) {
			return
		}
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" || state == "" {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "missing code or state")
			return
		}
		if v, ok := p.(callbackValidator); ok {
			if err := v.ValidateCallback(r.Context(), r.URL.Query()); err != nil {
				h.WriteError(w, http.StatusForbidden, "Forbidden", err.Error())
				return
			}
		}
		// Carry the callback query into the persist flow so a provider's
		// DeriveAPIEndpoint can read redirect-only params (e.g. Clover's merchant_id).
		ctx := client.WithCallbackQuery(r.Context(), r.URL.Query())
		if err := p.Callback(ctx, code, state); err != nil {
			if h.Journal != nil {
				h.Journal.Error("oauth callback failed for " + name + ": " + err.Error())
			}
			h.WriteError(w, http.StatusInternalServerError, "OAuth Callback Failed", "callback processing failed")
			return
		}
		http.Redirect(w, r, h.FrontendReturnURL+"?"+name+"=success", http.StatusFound)
	}
}

// test re-validates a stored connection (POST: it makes an outbound call and
// updates status/last_checked). entity_id scopes which connection.
func (h *OAuthConnectHandler) test(_ string, p client.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.RequireMethod(w, r, http.MethodPost) {
			return
		}
		partnerID, ok := h.RequirePartner(w, r)
		if !ok {
			return
		}
		entityID, err := parseEntity(r.URL.Query().Get(client.StateEntityKey))
		if err != nil {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
			return
		}
		ctx := client.WithEntity(r.Context(), entityID)
		if err := p.Test(ctx, partnerID); err != nil {
			common.WriteJSON(w, http.StatusOK, map[string]string{"status": "error", "message": err.Error()})
			return
		}
		common.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
