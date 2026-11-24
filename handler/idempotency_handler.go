package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/idempotency"
)

const (
	IdempotencyKeyHeader      = "Idempotency-Key"
	IdempotencyReplayedHeader = "Idempotency-Replayed"

	maxIdempotencyKey = 255
)

// replayedHeaders are the only handler headers recorded; cookies never are.
var replayedHeaders = []string{"Content-Type", "Content-Disposition", "Location", "ETag"}

func init() {
	RegisterErrorCode(idempotency.ErrKeyReused, http.StatusUnprocessableEntity, "idempotency_key_reused")
	RegisterErrorCode(idempotency.ErrInFlight, http.StatusConflict, "idempotency_in_flight")
	RegisterErrorCode(idempotency.ErrOutcomeUnknown, http.StatusConflict, "idempotency_outcome_unknown")
}

// IdempotencyHandler gives routes the Idempotency-Key contract: a repeated
// request gets the first response instead of running again. Wrap routes whose
// responses may be stored; one returning credentials must not be wrapped.
type IdempotencyHandler struct {
	AbstractHandler
	Requests *idempotency.RequestStore
}

type recordedResponse struct {
	Status int               `json:"status"`
	Header map[string]string `json:"header"`
	Body   []byte            `json:"body"`
}

// Wrap applies the contract to every route. A safe method, or a request without
// the header, passes through.
func (h *IdempotencyHandler) Wrap(routes map[string]func(http.ResponseWriter, *http.Request)) map[string]func(http.ResponseWriter, *http.Request) {
	wrapped := make(map[string]func(http.ResponseWriter, *http.Request), len(routes))
	for path, next := range routes {
		wrapped[path] = h.wrap(next)
	}
	return wrapped
}

func (h *IdempotencyHandler) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next(w, r)
			return
		}
		values := r.Header.Values(IdempotencyKeyHeader)
		if len(values) == 0 {
			next(w, r)
			return
		}
		clientKey, ok := h.parseKey(values)
		if !ok {
			h.WriteRequestError(r, w, http.StatusBadRequest, "Bad Request", "Idempotency-Key must be one value of 1 to 255 visible ASCII characters without quotes, commas or backslashes")
			return
		}
		caller, err := h.caller(r)
		if err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, config.Config().MaxRequestSize))
		if err != nil {
			status := http.StatusBadRequest
			if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
				status = http.StatusRequestEntityTooLarge
			}
			h.WriteRequestError(r, w, status, http.StatusText(status), "Failed to read request body")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		id, err := json.Marshal([]any{caller, r.Method, r.URL.RequestURI(), clientKey})
		if err != nil {
			h.WriteServiceError(w, r, err)
			return
		}
		h.serve(w, r, next, common.Sha256Hex(string(id)), common.Sha256Hex(string(body)))
	}
}

func (h *IdempotencyHandler) serve(w http.ResponseWriter, r *http.Request, next http.HandlerFunc, key, digest string) {
	fence, stored, err := h.Requests.Begin(r.Context(), key, digest, config.Config().IdempotencyWindow)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	if fence == "" {
		h.replay(w, r, stored)
		return
	}
	rec := &bufferedResponse{ResponseWriter: w}
	returned := false
	defer func() {
		if !returned {
			h.logSettle(r, h.Requests.MarkUnknown(r.Context(), key, fence))
		}
	}()
	next(rec, r)
	returned = true
	rec.WriteHeader(http.StatusOK)
	h.logSettle(r, h.settle(r, rec, key, fence))
	if !rec.overflow {
		h.logSettle(r, rec.flush())
	}
}

// settle records the response. A request refused before it ran (not signed in,
// not permitted, rate limited) releases its key for a retry.
func (h *IdempotencyHandler) settle(r *http.Request, rec *bufferedResponse, key, fence string) error {
	if rec.overflow {
		return h.Requests.MarkUnknown(r.Context(), key, fence)
	}
	switch rec.status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return h.Requests.Release(r.Context(), key, fence)
	}
	header := map[string]string{}
	for _, name := range replayedHeaders {
		if v := rec.Header().Get(name); v != "" {
			header[name] = v
		}
	}
	stored, err := json.Marshal(recordedResponse{Status: rec.status, Header: header, Body: rec.body.Bytes()})
	if err != nil {
		return err
	}
	return h.Requests.Complete(r.Context(), key, fence, stored)
}

func (h *IdempotencyHandler) replay(w http.ResponseWriter, r *http.Request, stored []byte) {
	var res recordedResponse
	if err := json.Unmarshal(stored, &res); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	for name, v := range res.Header {
		w.Header().Set(name, v)
	}
	w.Header().Set(IdempotencyReplayedHeader, "true")
	out := &bufferedResponse{ResponseWriter: w, status: res.Status}
	out.body.Write(res.Body)
	h.logSettle(r, out.flush())
}

// parseKey accepts a structured-field string or the bare value most clients send.
func (h *IdempotencyHandler) parseKey(values []string) (string, bool) {
	key := values[0]
	if len(key) > 1 && key[0] == '"' && key[len(key)-1] == '"' {
		key = key[1 : len(key)-1]
	}
	invalid := func(c rune) bool { return c <= ' ' || c > '~' || c == '"' || c == '\\' || c == ',' }
	return key, len(values) == 1 && key != "" && len(key) <= maxIdempotencyKey && !strings.ContainsFunc(key, invalid)
}

// caller identifies who the key belongs to, within the partner they act for.
func (h *IdempotencyHandler) caller(r *http.Request) ([]any, error) {
	if session := h.ParseSession(r); session != nil {
		return []any{"user", session.Id, session.PartnerId}, nil
	}
	s, err := common.CallerSessionFromContext(r.Context())
	if err != nil {
		return nil, err
	}
	if s.APIKeyID > 0 {
		return []any{"api_key", s.APIKeyID, s.PartnerID}, nil
	}
	issuer := ""
	if s.Principal != nil {
		issuer = s.Principal.Issuer
	}
	return []any{"subject", issuer, s.Subject, s.UserID, s.PartnerID}, nil
}

func (h *IdempotencyHandler) logSettle(r *http.Request, err error) {
	if err != nil {
		h.logProblem(r, common.RequestIDFromContext(r.Context()), http.StatusInternalServerError, "idempotent request", err.Error())
	}
}
