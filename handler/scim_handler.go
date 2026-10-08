package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/sso"
)

const (
	scimPath        = common.PublicPrefix + "/scim/v2"
	scimContentType = "application/scim+json"
)

func init() {
	RegisterErrorCode(sso.ErrSCIMTooMany, http.StatusConflict, "too_many_provisioning_tokens")
	RegisterErrorCode(sso.ErrSCIMNotFound, http.StatusNotFound, "not_found")
	RegisterErrorCode(sso.ErrSCIMInvalidValue, http.StatusBadRequest, "invalid_value")
}

// scimStatuses maps provisioning errors to RFC 7644 statuses and scimType.
var scimStatuses = []struct {
	err      error
	status   int
	scimType string
}{
	{sso.ErrSCIMUnauthorized, http.StatusUnauthorized, ""},
	{sso.ErrSCIMNotFound, http.StatusNotFound, ""},
	{sso.ErrSCIMConflict, http.StatusConflict, "uniqueness"},
	{sso.ErrSCIMInvalidFilter, http.StatusBadRequest, "invalidFilter"},
	{sso.ErrSCIMInvalidPath, http.StatusBadRequest, "invalidPath"},
	{sso.ErrSCIMTooMany, http.StatusRequestEntityTooLarge, "tooMany"},
	{sso.ErrSCIMInvalidValue, http.StatusBadRequest, "invalidValue"},
}

// SCIMHandler serves SCIM 2.0 (RFC 7644) to a partner's directory under
// /public/scim/v2, authenticated by a provisioning token rather than a
// session, and the table actions that issue and revoke those tokens.
type SCIMHandler struct {
	AbstractHandler
	DB           port.DatabaseRepository
	Provisioning *sso.Provisioning
	// PublicBaseURL is this API's origin, used in resource locations.
	PublicBaseURL string
}

// PublicRoutes mounts the SCIM endpoints.
func (h *SCIMHandler) PublicRoutes() map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		scimPath + "/ServiceProviderConfig": h.serviceProviderConfig,
		scimPath + "/ResourceTypes":         h.resourceTypes,
		scimPath + "/Schemas":               h.schemas,
		scimPath + "/Users":                 h.authenticated(h.users),
		scimPath + "/Users/{id}":            h.authenticated(h.user),
		scimPath + "/Groups":                h.authenticated(h.groups),
		scimPath + "/Groups/{id}":           h.authenticated(h.group),
	}
}

// Routes mounts the partner_scim_token table actions under apiPrefix.
func (h *SCIMHandler) Routes(apiPrefix string) map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		TableActionPath(apiPrefix, "partner_scim_token", "generate"): WrapTableAction(
			h.DB, h.UserService, "PARTNER_SCIM_TOKEN", "GENERATE", "partner_scim_token", h.GenerateToken),
		TableActionPath(apiPrefix, "partner_scim_token", "revoke"): WrapTableAction(
			h.DB, h.UserService, "PARTNER_SCIM_TOKEN", "REVOKE", "partner_scim_token", h.RevokeToken),
	}
}

// GenerateToken issues a provisioning token, shown once.
func (h *SCIMHandler) GenerateToken(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Caption     string      `json:"caption"`
		ExpiresDays json.Number `json:"expires_days"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	days := 0
	if req.ExpiresDays != "" {
		v, err := strconv.Atoi(string(req.ExpiresDays))
		if err != nil {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "expires_days must be a whole number")
			return
		}
		days = v
	}
	id, token, err := h.Provisioning.IssueToken(r.Context(), session.PartnerId, session.Id, req.Caption, days)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	common.WriteJSON(w, http.StatusOK, map[string]any{"id": id, "token": token, "scimBaseUrl": strings.TrimRight(h.PublicBaseURL, "/") + scimPath})
}

// RevokeToken revokes one of the session partner's tokens.
func (h *SCIMHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if err := h.Provisioning.RevokeToken(r.Context(), session.PartnerId, req.ID); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"id": req.ID, "revoked": true})
}

func (h *SCIMHandler) authenticated(next func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			h.scimError(w, r, sso.ErrSCIMUnauthorized)
			return
		}
		partnerID, err := h.Provisioning.Authenticate(r.Context(), parts[1])
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		next(w, r, partnerID)
	}
}

func (h *SCIMHandler) users(w http.ResponseWriter, r *http.Request, partnerID int64) {
	switch r.Method {
	case http.MethodGet:
		start, count, err := pageParams(r)
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		list, err := h.Provisioning.ListUsers(r.Context(), partnerID, r.URL.Query().Get("filter"), start, count)
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		for _, u := range list.Resources {
			h.locate(u.Meta, "Users", u.ID)
		}
		h.scimJSON(w, http.StatusOK, list)
	case http.MethodPost:
		var in sso.SCIMUser
		if !h.scimRead(w, r, &in) {
			return
		}
		u, err := h.Provisioning.CreateUser(r.Context(), partnerID, &in)
		h.userResult(w, r, http.StatusCreated, u, err)
	default:
		h.methodNotAllowed(w, r)
	}
}

func (h *SCIMHandler) user(w http.ResponseWriter, r *http.Request, partnerID int64) {
	id := r.PathValue("id")
	switch r.Method {
	case http.MethodGet:
		u, err := h.Provisioning.GetUser(r.Context(), partnerID, id)
		h.userResult(w, r, http.StatusOK, u, err)
	case http.MethodPut:
		var in sso.SCIMUser
		if !h.scimRead(w, r, &in) {
			return
		}
		u, err := h.Provisioning.ReplaceUser(r.Context(), partnerID, id, &in)
		h.userResult(w, r, http.StatusOK, u, err)
	case http.MethodPatch:
		var patch sso.SCIMPatch
		if !h.scimRead(w, r, &patch) {
			return
		}
		u, err := h.Provisioning.PatchUser(r.Context(), partnerID, id, patch.Operations)
		h.userResult(w, r, http.StatusOK, u, err)
	case http.MethodDelete:
		if err := h.Provisioning.DeleteUser(r.Context(), partnerID, id); err != nil {
			h.scimError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		h.methodNotAllowed(w, r)
	}
}

func (h *SCIMHandler) groups(w http.ResponseWriter, r *http.Request, partnerID int64) {
	switch r.Method {
	case http.MethodGet:
		start, count, err := pageParams(r)
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		list, err := h.Provisioning.ListGroups(r.Context(), partnerID, r.URL.Query().Get("filter"), start, count)
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		for _, g := range list.Resources {
			h.locate(g.Meta, "Groups", g.ID)
		}
		h.scimJSON(w, http.StatusOK, list)
	case http.MethodPost:
		var in sso.SCIMGroup
		if !h.scimRead(w, r, &in) {
			return
		}
		g, err := h.Provisioning.CreateGroup(r.Context(), partnerID, &in)
		h.groupResult(w, r, http.StatusCreated, g, err)
	default:
		h.methodNotAllowed(w, r)
	}
}

func (h *SCIMHandler) group(w http.ResponseWriter, r *http.Request, partnerID int64) {
	id := r.PathValue("id")
	switch r.Method {
	case http.MethodGet:
		withMembers := !strings.Contains(strings.ToLower(r.URL.Query().Get("excludedAttributes")), "members")
		g, err := h.Provisioning.GetGroup(r.Context(), partnerID, id, withMembers)
		h.groupResult(w, r, http.StatusOK, g, err)
	case http.MethodPut:
		var in sso.SCIMGroup
		if !h.scimRead(w, r, &in) {
			return
		}
		g, err := h.Provisioning.ReplaceGroup(r.Context(), partnerID, id, &in)
		h.groupResult(w, r, http.StatusOK, g, err)
	case http.MethodPatch:
		var patch sso.SCIMPatch
		if !h.scimRead(w, r, &patch) {
			return
		}
		g, err := h.Provisioning.PatchGroup(r.Context(), partnerID, id, patch.Operations)
		h.groupResult(w, r, http.StatusOK, g, err)
	case http.MethodDelete:
		if err := h.Provisioning.DeleteGroup(r.Context(), partnerID, id); err != nil {
			h.scimError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		h.methodNotAllowed(w, r)
	}
}

func (h *SCIMHandler) userResult(w http.ResponseWriter, r *http.Request, status int, u *sso.SCIMUser, err error) {
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	h.locate(u.Meta, "Users", u.ID)
	h.scimJSON(w, status, u)
}

func (h *SCIMHandler) groupResult(w http.ResponseWriter, r *http.Request, status int, g *sso.SCIMGroup, err error) {
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	h.locate(g.Meta, "Groups", g.ID)
	h.scimJSON(w, status, g)
}

func (h *SCIMHandler) locate(meta *sso.SCIMMeta, resource, id string) {
	if meta != nil {
		meta.Location = strings.TrimRight(h.PublicBaseURL, "/") + scimPath + "/" + resource + "/" + id
	}
}

func (h *SCIMHandler) scimRead(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, config.Config().MaxRequestSize))
	if err != nil {
		h.scimError(w, r, fmt.Errorf("%w: body: %v", sso.ErrSCIMInvalidValue, err))
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(v); err != nil {
		h.scimError(w, r, fmt.Errorf("%w: malformed JSON", sso.ErrSCIMInvalidValue))
		return false
	}
	if err := requireJSONEOF(dec); err != nil {
		h.scimError(w, r, fmt.Errorf("%w: malformed JSON", sso.ErrSCIMInvalidValue))
		return false
	}
	return true
}

func (h *SCIMHandler) scimJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scimContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// scimError writes an RFC 7644 error. Unexpected failures are a generic 500
// with the cause only in the journal.
func (h *SCIMHandler) scimError(w http.ResponseWriter, r *http.Request, err error) {
	status, scimType, detail := http.StatusInternalServerError, "", "internal error"
	for _, s := range scimStatuses {
		if errors.Is(err, s.err) {
			status, scimType, detail = s.status, s.scimType, err.Error()
			break
		}
	}
	if status == http.StatusInternalServerError && h.Journal != nil {
		h.Journal.Error(fmt.Sprintf("scim %s %s: %v", r.Method, r.URL.Path, err))
	}
	body := map[string]any{"schemas": []string{sso.SchemaError}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	h.scimJSON(w, status, body)
}

func (h *SCIMHandler) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{"schemas": []string{sso.SchemaError}, "status": "405", "detail": r.Method + " is not supported here"}
	h.scimJSON(w, http.StatusMethodNotAllowed, body)
}

func pageParams(r *http.Request) (int, int, error) {
	parse := func(name string) (int, error) {
		raw := r.URL.Query().Get(name)
		if raw == "" {
			return 0, nil
		}
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return 0, fmt.Errorf("%w: %s must be a non-negative integer", sso.ErrSCIMInvalidValue, name)
		}
		return value, nil
	}
	start, err := parse("startIndex")
	if err != nil {
		return 0, 0, err
	}
	count, err := parse("count")
	return start, count, err
}

func (h *SCIMHandler) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}
	h.scimJSON(w, http.StatusOK, map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": config.Config().MaxListPageSize},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token", "description": "Provisioning token issued by a partner administrator", "primary": true}},
	})
}

func (h *SCIMHandler) resourceTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}
	h.scimJSON(w, http.StatusOK, sso.SCIMList[map[string]any]{
		Schemas: []string{sso.SchemaListResponse}, TotalResults: 2, StartIndex: 1, ItemsPerPage: 2,
		Resources: []map[string]any{
			{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": sso.SchemaUser},
			{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": sso.SchemaGroup},
		},
	})
}

func (h *SCIMHandler) schemas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}
	attr := func(name, typ string, required bool) map[string]any {
		return map[string]any{"name": name, "type": typ, "multiValued": false, "required": required, "mutability": "readWrite", "returned": "default", "uniqueness": "none"}
	}
	h.scimJSON(w, http.StatusOK, sso.SCIMList[map[string]any]{
		Schemas: []string{sso.SchemaListResponse}, TotalResults: 2, StartIndex: 1, ItemsPerPage: 2,
		Resources: []map[string]any{
			{"id": sso.SchemaUser, "name": "User", "attributes": []map[string]any{
				attr("userName", "string", true), attr("externalId", "string", false), attr("name", "complex", false),
				attr("displayName", "string", false), attr("emails", "complex", false), attr("active", "boolean", false)}},
			{"id": sso.SchemaGroup, "name": "Group", "attributes": []map[string]any{
				attr("displayName", "string", true), attr("externalId", "string", false), attr("members", "complex", false)}},
		},
	})
}
