package handler

import (
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/rest"
)

type CacheHandler struct {
	AbstractHandler
	RestService *rest.RestService
}

// GetApplicationData returns the per-user cache projection (constants,
// tables, menu, REST API definitions). Requires an authenticated user —
// the projection is scoped by user id and unauthenticated callers must
// not be able to enumerate it.
func (h *CacheHandler) GetApplicationData(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	userID, ok := h.RequireUser(w, r)
	if !ok {
		return
	}
	response, err := h.RestService.GetClientCache(r.Context(), userID)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "internal server error")
		return
	}
	common.WriteJSON(w, http.StatusOK, response)
}

// TypeScriptTables emits the TypeScript class definitions used by the web
// UI generator. Requires an authenticated session and the optional
// baseclass query parameter is restricted to a conservative identifier
// alphabet so it cannot be used to inject TypeScript into the output.
func (h *CacheHandler) TypeScriptTables(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	if _, ok := h.RequireUser(w, r); !ok {
		return
	}
	baseclass := r.URL.Query().Get("baseclass")
	if !isSafeIdent(baseclass) {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid baseclass")
		return
	}
	tables := h.RestService.TypeScriptTables(r.Context(), baseclass, 0)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	for _, data := range tables {
		w.Write(*data)
		w.Write([]byte("\n\n"))
	}
}

// isSafeIdent returns true when s is empty or is a conservative ASCII
// identifier. Used to gate query parameters that flow into generated
// source so an attacker cannot inject TypeScript via the response.
func isSafeIdent(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		case r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}
