package handler

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

// sessionCtxKey is the context key under which ParseSession caches the
// validated session for the lifetime of one request, avoiding repeated
// HMAC-verify cost when an authenticated handler calls GetUser /
// GetPartner / RequireSession back-to-back.
type sessionCtxKey struct{}

// sessionMissCtxKey marks "we already tried to parse and there was no
// valid session" so subsequent ParseSession calls don't re-attempt HMAC
// verification of a missing/invalid token.
type sessionMissCtxKey struct{}

type AbstractHandler struct {
	UserService user.UserService
}

// ParseSession returns the JWT-bearing session on the request, or nil when
// the Authorization header is missing, malformed, or fails JWT validation.
// Stateless — no DB call.
//
// The first call per request memoizes the result in the request context
// (under sessionCtxKey / sessionMissCtxKey) so subsequent helpers
// (GetUser, GetPartner, RequireSession, ReadAuthRequest) on the same
// request reuse the validated session instead of re-running HMAC verify.
// Tightens the per-request CPU footprint on authenticated handlers that
// historically parsed the JWT 2–3× on the same path.
//
// The cache is per-request (not process-wide) so a session refresh on
// the next request still parses freshly. Callers that want the canonical
// 401-on-miss behaviour should use RequireSession instead.
func (h *AbstractHandler) ParseSession(r *http.Request) *model.UserSession {
	ctx := r.Context()
	if v, ok := ctx.Value(sessionCtxKey{}).(*model.UserSession); ok {
		return v
	}
	if _, miss := ctx.Value(sessionMissCtxKey{}).(struct{}); miss {
		return nil
	}
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		stashSessionMiss(r)
		return nil
	}
	tokenStr := strings.TrimPrefix(auth, "Bearer ")
	session, err := h.UserService.ParseJWT(tokenStr)
	if err != nil || session == nil {
		stashSessionMiss(r)
		return nil
	}
	stashSession(r, session)
	return session
}

// stashSession caches a successfully-parsed session on the request so
// subsequent ParseSession calls in the same request return without
// re-verifying the JWT. Mutates the *http.Request in place by swapping
// in a derived context — safe because every helper reads the context
// from the request and Request itself is not shared across goroutines.
func stashSession(r *http.Request, session *model.UserSession) {
	ctx := context.WithValue(r.Context(), sessionCtxKey{}, session)
	*r = *r.WithContext(ctx)
}

func stashSessionMiss(r *http.Request) {
	ctx := context.WithValue(r.Context(), sessionMissCtxKey{}, struct{}{})
	*r = *r.WithContext(ctx)
}

// GetUser returns the authenticated user id, or -1 when there is no session.
func (h *AbstractHandler) GetUser(r *http.Request) int {
	if session := h.ParseSession(r); session != nil {
		return session.Id
	}
	return -1
}

// GetPartner returns the authenticated partner id, or -1 when there is no
// session or the session has no partner association.
func (h *AbstractHandler) GetPartner(r *http.Request) int64 {
	if session := h.ParseSession(r); session != nil {
		return session.PartnerId
	}
	return -1
}

// RequireSession returns the session in the JWT, or writes a 401 RFC 7807
// envelope and returns ok=false when no session is present. Callers should
// early-return on ok=false:
//
//	session, ok := h.RequireSession(w, r)
//	if !ok { return }
func (h *AbstractHandler) RequireSession(w http.ResponseWriter, r *http.Request) (*model.UserSession, bool) {
	session := h.ParseSession(r)
	if session == nil {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "Invalid or missing session")
		return nil, false
	}
	return session, true
}

// RequireUser returns the authenticated user id, or writes a 401 and
// returns ok=false when none is present.
func (h *AbstractHandler) RequireUser(w http.ResponseWriter, r *http.Request) (int, bool) {
	session, ok := h.RequireSession(w, r)
	if !ok {
		return 0, false
	}
	return session.Id, true
}

// RequirePartner returns the authenticated partner id, or writes a 401 and
// returns ok=false when no partner is associated with the session.
func (h *AbstractHandler) RequirePartner(w http.ResponseWriter, r *http.Request) (int64, bool) {
	session, ok := h.RequireSession(w, r)
	if !ok {
		return 0, false
	}
	if session.PartnerId < 0 {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "No partner associated with session")
		return 0, false
	}
	return session.PartnerId, true
}

// ReadRequest reads the request body (capped at *common.MaxRequestSize) and
// JSON-unmarshals it into req. Writes 400 on read or unmarshal failure and
// returns ok=false. Returns true with req populated on success. Use for
// public endpoints that do not require an authenticated session.
func (h *AbstractHandler) ReadRequest(w http.ResponseWriter, r *http.Request, req any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, *common.MaxRequestSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "Failed to read request body")
		return false
	}
	if err := json.Unmarshal(body, req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON: "+err.Error())
		return false
	}
	return true
}

// ReadAuthRequest combines RequireSession and ReadRequest. Returns the
// session and ok=true on success; on any failure (no JWT, oversize body,
// bad JSON) writes the appropriate response and returns (nil, false).
func (h *AbstractHandler) ReadAuthRequest(w http.ResponseWriter, r *http.Request, req any) (*model.UserSession, bool) {
	session, ok := h.RequireSession(w, r)
	if !ok {
		return nil, false
	}
	if !h.ReadRequest(w, r, req) {
		return nil, false
	}
	return session, true
}

// ReadStrictRequest is the strict-schema sibling of ReadRequest:
// requests carrying JSON fields not declared on req return 400.
// Use this on security-sensitive endpoints (Disable2FA, DeleteAccount,
// payment-method delete) where an injected unknown field could
// camouflage an attempt to override an internal flag the JSON gateway
// in front of keel didn't catch.
//
// Hot REST paths should keep using ReadRequest — strict-schema parsing
// is a nice-to-have, not a hot-path concern, and breaking client
// compatibility on a typo would surface as a customer-visible bug.
func (h *AbstractHandler) ReadStrictRequest(w http.ResponseWriter, r *http.Request, req any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, *common.MaxRequestSize)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(req); err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "Invalid JSON: "+err.Error())
		return false
	}
	return true
}

// PartnerFromCtx returns the partner id injected by APIKeyMiddleware after
// validating the X-API-Key header. Use this in /pubapi/* handlers. Returns
// -1 if the request never went through the middleware. Note: this reads
// from the request context, NOT the JWT — pubapi traffic has no JWT.
func (h *AbstractHandler) PartnerFromCtx(r *http.Request) int64 {
	if v, ok := r.Context().Value(common.PartnerID).(int64); ok {
		return v
	}
	return -1
}

// HasScope reports whether the API key's scope claim contains scope.
// Scopes are stored in the request context (via APIKeyMiddleware) as a
// comma-separated string.
func (h *AbstractHandler) HasScope(r *http.Request, scope string) bool {
	raw, _ := r.Context().Value(common.Scopes).(string)
	if raw == "" || scope == "" {
		return false
	}
	for _, s := range strings.Split(raw, ",") {
		if strings.TrimSpace(s) == scope {
			return true
		}
	}
	return false
}

// RequireScope returns true when the API key's scopes include scope, or
// writes a 403 and returns false otherwise.
func (h *AbstractHandler) RequireScope(w http.ResponseWriter, r *http.Request, scope string) bool {
	if !h.HasScope(r, scope) {
		h.WriteError(w, http.StatusForbidden, "Forbidden", fmt.Sprintf("scope %q required", scope))
		return false
	}
	return true
}

// RequireFields validates that every value in fields is non-empty after
// TrimSpace. On any miss it writes a 400 listing the missing field names
// (alphabetically) and returns false; on full satisfaction returns true.
// Map keys are the user-facing field names that appear in the 400 detail.
//
//	if !h.RequireFields(w, map[string]string{
//	    "email":    req.Email,
//	    "password": req.Password,
//	}) { return }
func (h *AbstractHandler) RequireFields(w http.ResponseWriter, fields map[string]string) bool {
	var missing []string
	for name, value := range fields {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return true
	}
	sort.Strings(missing)
	h.WriteError(w, http.StatusBadRequest, "Bad Request",
		"missing required field(s): "+strings.Join(missing, ", "))
	return false
}

// RequireMethod returns true when r.Method is one of the allowed methods,
// or writes a 405 with an Allow header and returns false. One-line guard
// at the top of HTTP-method-restricted handlers:
//
//	if !h.RequireMethod(w, r, http.MethodPost) { return }
//
// For multi-method endpoints, pass each:
//
//	if !h.RequireMethod(w, r, http.MethodPost, http.MethodDelete) { return }
func (h *AbstractHandler) RequireMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	h.WriteError(w, http.StatusMethodNotAllowed, "Method Not Allowed",
		"Use "+strings.Join(methods, ", "))
	return false
}

// RequireQueryInt64 reads r.URL.Query().Get(name), parses it as int64, and
// returns (value, true) on success. On missing or unparseable value, writes
// a 400 RFC 7807 envelope with a descriptive detail and returns (0, false).
//
//	id, ok := h.RequireQueryInt64(w, r, "id")
//	if !ok { return }
func (h *AbstractHandler) RequireQueryInt64(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request",
			fmt.Sprintf("missing required query parameter %q", name))
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request",
			fmt.Sprintf("invalid %s: %s", name, err.Error()))
		return 0, false
	}
	return v, true
}

// ProblemDetail is the RFC 7807 envelope returned by WriteError.
// Hoisted to package scope so tests and downstream callers can decode
// against a stable type instead of an anonymous struct.
type ProblemDetail struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Instance  string `json:"instance,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// WriteError writes an RFC 7807 problem-detail response. Status 5xx
// responses get a stable opaque request id so operators can correlate
// the user-visible error to a structured log line, and the caller's
// detail string is replaced with a generic message — internal errors
// are not safe to leak to unauthenticated clients verbatim. 4xx
// passes the caller's detail through unchanged because validation
// messages are intentionally surfaced to the user.
//
// The request id surfaced in the response prefers the value injected
// by upstream request-id middleware (via context.WithValue(ctx,
// common.RequestID, "<token>"); see WriteRequestError for the
// request-aware variant). When no middleware is wired, a fresh
// opaque token is generated per call so 5xx responses still carry a
// usable correlation id.
func (h *AbstractHandler) WriteError(w http.ResponseWriter, status int, title, detail string) {
	h.writeError(nil, w, status, title, detail)
}

// WriteRequestError is the request-aware sibling of WriteError. When
// request-id middleware injects a value via context.WithValue(r.Context(),
// common.RequestID, ...), the surfaced request_id matches whatever
// that middleware bound — so a single id ties the response, the
// access log, and the application log together (P2-09).
//
// Existing handlers that already call WriteError continue to work
// unchanged; consumers wanting cross-log correlation should switch
// to WriteRequestError where the request is in scope.
func (h *AbstractHandler) WriteRequestError(r *http.Request, w http.ResponseWriter, status int, title, detail string) {
	h.writeError(r, w, status, title, detail)
}

func (h *AbstractHandler) writeError(r *http.Request, w http.ResponseWriter, status int, title, detail string) {
	requestID := ""
	if r != nil {
		if v, ok := r.Context().Value(common.RequestID).(string); ok && v != "" {
			requestID = v
		}
	}
	if requestID == "" {
		requestID = newRequestID()
	}
	if status >= http.StatusInternalServerError {
		// 5xx is operator-territory; never echo internal context.
		detail = "internal server error — see request_id in your logs"
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	problem := ProblemDetail{
		Type:      "about:blank",
		Title:     title,
		Status:    status,
		Detail:    detail,
		RequestID: requestID,
	}
	_ = json.NewEncoder(w).Encode(problem)
}

// newRequestID returns a fresh opaque token used as the per-request
// correlation id when no middleware-bound value is in scope. Twelve
// alphanumeric characters (~71 bits of entropy) is plenty to keep
// collisions rare across access-log volume.
//
// Each character is drawn uniformly from the alphabet via crypto/rand
// rather than `byte%len(alphabet)`, which would skew the first
// (256 mod len) characters by ~1 unit of bias. Negligible in practice
// but trivial to remove. On RNG failure a process-startup-derived
// fallback id is returned so 5xx responses always carry a usable
// correlation id rather than an empty string.
func newRequestID() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 12)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		n, err := crand.Int(crand.Reader, max)
		if err != nil {
			return fallbackRequestID()
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out)
}

// fallbackRequestID is the last-resort id used when crypto/rand fails
// (extremely unlikely on supported platforms but reachable on a kernel
// that's exhausted entropy or jailed). The id is unique-per-process
// monotonic, suffixed onto a startup nonce so two processes don't
// collide. Producing a stable correlation id always — instead of an
// empty string — is the design goal.
var fallbackCounter atomic.Uint64

// fallbackPrefix is rolled at process start. Best-effort: if even the
// fallback rand fails we use a constant — the resulting ids still
// correlate within a single process via the counter suffix.
var fallbackPrefix = func() string {
	var b [4]byte
	if _, err := crand.Read(b[:]); err == nil {
		return fmt.Sprintf("nokey%x", b)
	}
	return "nokey0000"
}()

func fallbackRequestID() string {
	return fmt.Sprintf("%s-%d", fallbackPrefix, fallbackCounter.Add(1))
}

// ScrubAuthHeader returns a derived *http.Request with secret-bearing
// headers (Authorization, X-API-Key, Cookie) replaced by "<scrubbed>".
// Headers on the returned request are cloned so subsequent handler
// code reading r.Header.Get("Authorization") sees the original value;
// only the log-formatter sees the scrubbed copy. Callers wire this
// into their log-formatter hooks:
//
//	logger.LogRequest(handler.ScrubAuthHeader(r))
//
// Pre-v0.5 this mutated r.Header in place — surprising and incorrect
// when the same request continued to handler code expecting the
// real Authorization value.
func ScrubAuthHeader(r *http.Request) *http.Request {
	if r == nil {
		return r
	}
	cloned := r.Clone(r.Context())
	if cloned.Header == nil {
		return cloned
	}
	if cloned.Header.Get("Authorization") != "" {
		cloned.Header.Set("Authorization", "<scrubbed>")
	}
	if cloned.Header.Get("X-API-Key") != "" {
		cloned.Header.Set("X-API-Key", "<scrubbed>")
	}
	if cloned.Header.Get("Cookie") != "" {
		cloned.Header.Set("Cookie", "<scrubbed>")
	}
	return cloned
}
