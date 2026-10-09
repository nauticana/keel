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
	{sso.ErrSCIMNoTarget, http.StatusBadRequest, "noTarget"},
	{sso.ErrSCIMMutability, http.StatusBadRequest, "mutability"},
	// Operation and member limits bound values, not bytes; tooMany is only for filters.
	{sso.ErrSCIMTooMany, http.StatusBadRequest, "invalidValue"},
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
		scimPath + "/ResourceTypes/{id}":    h.resourceType,
		scimPath + "/Schemas":               h.schemas,
		scimPath + "/Schemas/{id}":          h.schema,
		scimPath + "/Me":                    h.me,
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
		q, err := listQuery(r)
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		list, err := h.Provisioning.ListUsers(r.Context(), partnerID, q)
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		for _, u := range list.Resources {
			h.locate(u.Meta, "Users", u.ID)
		}
		h.scimList(w, r, projection(r, sso.SchemaUser), list.TotalResults, list.StartIndex, list.Resources)
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
		q, err := listQuery(r)
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		q.Members = projection(r, sso.SchemaGroup).Includes("members")
		list, err := h.Provisioning.ListGroups(r.Context(), partnerID, q)
		if err != nil {
			h.scimError(w, r, err)
			return
		}
		for _, g := range list.Resources {
			h.locate(g.Meta, "Groups", g.ID)
		}
		h.scimList(w, r, projection(r, sso.SchemaGroup), list.TotalResults, list.StartIndex, list.Resources)
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
		g, err := h.Provisioning.GetGroup(r.Context(), partnerID, id, projection(r, sso.SchemaGroup).Includes("members"))
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
	h.resourceResult(w, r, status, sso.SchemaUser, h.locate(u.Meta, "Users", u.ID), u)
}

func (h *SCIMHandler) groupResult(w http.ResponseWriter, r *http.Request, status int, g *sso.SCIMGroup, err error) {
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	h.resourceResult(w, r, status, sso.SchemaGroup, h.locate(g.Meta, "Groups", g.ID), g)
}

// resourceResult writes a projected resource; a created one also carries
// its location in the Location header (RFC 7644 §3.3).
func (h *SCIMHandler) resourceResult(w http.ResponseWriter, r *http.Request, status int, schema, location string, resource any) {
	out, err := projection(r, schema).Apply(resource)
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	if status == http.StatusCreated {
		w.Header().Set("Location", location)
	}
	h.scimJSON(w, status, out)
}

func (h *SCIMHandler) scimList(w http.ResponseWriter, r *http.Request, p sso.SCIMProjection, total, start int, resources any) {
	var items []any
	raw, err := json.Marshal(resources)
	if err == nil {
		err = json.Unmarshal(raw, &items)
	}
	for i := 0; err == nil && i < len(items); i++ {
		items[i], err = p.Apply(items[i])
	}
	if err != nil {
		h.scimError(w, r, err)
		return
	}
	h.scimJSON(w, http.StatusOK, sso.SCIMList[any]{
		Schemas: []string{sso.SchemaListResponse}, TotalResults: total, StartIndex: start, ItemsPerPage: len(items), Resources: items,
	})
}

func projection(r *http.Request, schema string) sso.SCIMProjection {
	q := r.URL.Query()
	return sso.NewSCIMProjection(schema, q.Get("attributes"), q.Get("excludedAttributes"))
}

// locate sets and returns the resource's location.
func (h *SCIMHandler) locate(meta *sso.SCIMMeta, resource, id string) string {
	location := h.url(resource + "/" + id)
	if meta != nil {
		meta.Location = location
	}
	return location
}

func (h *SCIMHandler) url(path string) string {
	return strings.TrimRight(h.PublicBaseURL, "/") + scimPath + "/" + path
}

func (h *SCIMHandler) scimRead(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, config.Config().MaxRequestSize))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		h.scimWrite(w, http.StatusRequestEntityTooLarge, "", fmt.Sprintf("the body exceeds %d bytes", tooLarge.Limit))
		return false
	}
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
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	h.scimWrite(w, status, scimType, detail)
}

func (h *SCIMHandler) scimWrite(w http.ResponseWriter, status int, scimType, detail string) {
	body := map[string]any{"schemas": []string{sso.SchemaError}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	h.scimJSON(w, status, body)
}

func (h *SCIMHandler) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	h.scimWrite(w, http.StatusMethodNotAllowed, "", r.Method+" is not supported here")
}

// listQuery reads filter, startIndex and count. Out-of-range numbers are
// clamped by the service (RFC 7644 §3.4.2.4); only non-integers are refused.
func listQuery(r *http.Request) (sso.SCIMListQuery, error) {
	q := sso.SCIMListQuery{Filter: r.URL.Query().Get("filter")}
	parse := func(name string) (*int, error) {
		raw := r.URL.Query().Get(name)
		if raw == "" {
			return nil, nil
		}
		v, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s must be an integer", sso.ErrSCIMInvalidValue, name)
		}
		return &v, nil
	}
	start, err := parse("startIndex")
	if err != nil {
		return q, err
	}
	if start != nil {
		q.StartIndex = *start
	}
	q.Count, err = parse("count")
	return q, err
}

func (h *SCIMHandler) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}
	h.scimJSON(w, http.StatusOK, map[string]any{
		"schemas":               []string{sso.SchemaServiceConfig},
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": config.Config().MaxListPageSize},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token", "description": "Provisioning token issued by a partner administrator", "primary": true}},
		"meta":                  sso.SCIMMeta{ResourceType: "ServiceProviderConfig", Location: h.url("ServiceProviderConfig")},
	})
}

func (h *SCIMHandler) resourceTypeList() []map[string]any {
	item := func(id, endpoint, schema, description string) map[string]any {
		return map[string]any{"schemas": []string{sso.SchemaResourceType}, "id": id, "name": id, "endpoint": endpoint,
			"description": description, "schema": schema, "meta": sso.SCIMMeta{ResourceType: "ResourceType", Location: h.url("ResourceTypes/" + id)}}
	}
	return []map[string]any{item("User", "/Users", sso.SchemaUser, "User account"), item("Group", "/Groups", sso.SchemaGroup, "Group")}
}

func (h *SCIMHandler) resourceTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}
	types := h.resourceTypeList()
	h.scimJSON(w, http.StatusOK, sso.SCIMList[map[string]any]{
		Schemas: []string{sso.SchemaListResponse}, TotalResults: len(types), StartIndex: 1, ItemsPerPage: len(types), Resources: types,
	})
}

func (h *SCIMHandler) resourceType(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}
	for _, t := range h.resourceTypeList() {
		if t["id"] == r.PathValue("id") {
			h.scimJSON(w, http.StatusOK, t)
			return
		}
	}
	h.scimError(w, r, sso.ErrSCIMNotFound)
}

func (h *SCIMHandler) schemaList() []sso.SCIMSchema {
	schemas := sso.SCIMSchemas()
	for i := range schemas {
		schemas[i].Meta.Location = h.url("Schemas/" + schemas[i].ID)
	}
	return schemas
}

func (h *SCIMHandler) schemas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}
	schemas := h.schemaList()
	h.scimJSON(w, http.StatusOK, sso.SCIMList[sso.SCIMSchema]{
		Schemas: []string{sso.SchemaListResponse}, TotalResults: len(schemas), StartIndex: 1, ItemsPerPage: len(schemas), Resources: schemas,
	})
}

func (h *SCIMHandler) schema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.methodNotAllowed(w, r)
		return
	}
	for _, s := range h.schemaList() {
		if s.ID == r.PathValue("id") {
			h.scimJSON(w, http.StatusOK, s)
			return
		}
	}
	h.scimError(w, r, sso.ErrSCIMNotFound)
}

// me answers /Me: a provisioning token authenticates a directory, not a user (RFC 7644 §3.11).
func (h *SCIMHandler) me(w http.ResponseWriter, _ *http.Request) {
	h.scimWrite(w, http.StatusNotImplemented, "", "/Me is not supported")
}
