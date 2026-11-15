package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
)

// APIError carries an HTTP status alongside a message. Returning *APIError
// from a JSON-handler function sets the response status precisely; any
// other error type maps to 500.
type APIError struct {
	Status  int
	Msg     string
	Header  http.Header // response headers the error implies, e.g. Retry-After
	Details any         // the problem body's details member on a 4xx
}

func (e *APIError) Error() string { return e.Msg }

func (e *APIError) ErrorHeaders() http.Header { return e.Header }

var _ HeaderCarrier = (*APIError)(nil)

// NewAPIError is a convenience constructor — APIErr(http.StatusConflict, "...").
func NewAPIError(status int, msg string) *APIError { return &APIError{Status: status, Msg: msg} }

// WithHeader adds a response header and returns the error, so it can be built
// in one expression.
func (e *APIError) WithHeader(key, value string) *APIError {
	if e.Header == nil {
		e.Header = http.Header{}
	}
	e.Header.Add(key, value)
	return e
}

// HeaderCarrier lets a typed error carry Retry-After or Location through the
// handler boundary instead of losing it to the status+message mapping. Any
// error in the chain may implement it.
type HeaderCarrier interface {
	ErrorHeaders() http.Header
}

func writeErrorHeaders(w http.ResponseWriter, err error) {
	if carrier, ok := err.(HeaderCarrier); ok {
		for key, values := range carrier.ErrorHeaders() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			writeErrorHeaders(w, child)
		}
		return
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		writeErrorHeaders(w, wrapped.Unwrap())
	}
}

// JSONFunc is the signature of an authenticated JSON business function. body
// is nil when the request had none; a GET's query parameters arrive as a JSON
// object of strings (an array for a repeated name). Decode with common.DecodeJSON.
type JSONFunc func(ctx context.Context, session *model.UserSession, body json.RawMessage) (any, error)

// JSONPublicFunc is the signature of an anonymous JSON business function.
type JSONPublicFunc func(ctx context.Context, body json.RawMessage) (any, error)

// JSON wraps a business function with the method check ("" skips it), the
// session, a body bounded by max_request_size, and a 200 response. The session
// is bound to the context as its common.CallerSession. An *APIError sets its
// status; any other error is written by WriteServiceError.
func (h *AbstractHandler) JSON(method string, fn JSONFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if method != "" && !h.RequireMethod(w, r, method) {
			return
		}
		session, ok := h.RequireSession(w, r)
		if !ok {
			return
		}
		body, ok := readJSONBody(h, w, r)
		if !ok {
			return
		}
		ctx := r.Context()
		ctx = common.WithCallerSession(ctx, common.CallerSession{PartnerID: session.PartnerId, UserID: int64(session.Id),
			Subject: session.Subject, RequestID: common.RequestIDFromContext(ctx), Location: common.LocationFromContext(ctx)})
		result, err := fn(ctx, session, body)
		writeResult(h, w, r, result, err)
	}
}

// JSONPublic is JSON without authentication, for endpoints reachable before
// sign-in (signup, password-reset request, public lookup).
func (h *AbstractHandler) JSONPublic(method string, fn JSONPublicFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if method != "" && !h.RequireMethod(w, r, method) {
			return
		}
		body, ok := readJSONBody(h, w, r)
		if !ok {
			return
		}
		result, err := fn(r.Context(), body)
		writeResult(h, w, r, result, err)
	}
}

func readJSONBody(h *AbstractHandler, w http.ResponseWriter, r *http.Request) (json.RawMessage, bool) {
	if r.Method == http.MethodGet {
		return queryObject(h, w, r)
	}
	if r.Body == nil || r.ContentLength == 0 {
		return nil, true
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, config.Config().MaxRequestSize))
	if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
		h.WriteError(w, http.StatusRequestEntityTooLarge, "Request Entity Too Large", "request body exceeds max_request_size")
		return nil, false
	}
	var value any
	if err != nil || common.DecodeJSON(raw, &value) != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid JSON request body")
		return nil, false
	}
	return raw, true
}

func queryObject(h *AbstractHandler, w http.ResponseWriter, r *http.Request) (json.RawMessage, bool) {
	query := r.URL.Query()
	if len(query) == 0 {
		return nil, true
	}
	object := make(map[string]any, len(query))
	for name, values := range query {
		if len(values) == 1 {
			object[name] = values[0]
		} else {
			object[name] = values
		}
	}
	raw, err := json.Marshal(object)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid query parameters")
		return nil, false
	}
	return raw, true
}

func writeResult(h *AbstractHandler, w http.ResponseWriter, r *http.Request, result any, err error) {
	if err == nil {
		common.WriteJSON(w, http.StatusOK, result)
		return
	}
	writeErrorHeaders(w, err)
	if ae, ok := errors.AsType[*APIError](err); ok {
		h.writeProblem(r, w, ae.Status, http.StatusText(ae.Status), ae.Msg, "", "", ae.Details)
		return
	}
	h.WriteServiceError(w, r, err)
}
