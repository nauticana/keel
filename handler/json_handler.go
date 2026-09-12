package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

// APIError carries an HTTP status alongside a message. Returning *APIError
// from a JSON-handler function sets the response status precisely; any
// other error type maps to 500.
type APIError struct {
	Status int
	Msg    string
	Header http.Header // response headers the error implies, e.g. Retry-After
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

// JSONFunc is the signature of an authenticated JSON business function.
// body is nil when the request had no body.
type JSONFunc func(ctx context.Context, session *model.UserSession, body json.RawMessage) (any, error)

// JSONPublicFunc is the signature of an anonymous JSON business function.
type JSONPublicFunc func(ctx context.Context, body json.RawMessage) (any, error)

// JSON wraps a typed business function with method check, auth, JSON decode,
// dispatch, error→status mapping, and 200 response. Eliminates the 8-line
// prologue every JSON endpoint otherwise repeats. method "" disables the
// method check.
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
		result, err := fn(r.Context(), session, body)
		writeResult(h, w, result, err)
	}
}

// JSONPublic is JSON without authentication. Use for endpoints reachable
// before login (signup, password-reset request, public lookup).
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
		writeResult(h, w, result, err)
	}
}

func readJSONBody(h *AbstractHandler, w http.ResponseWriter, r *http.Request) (json.RawMessage, bool) {
	if r.Body == nil || r.ContentLength == 0 {
		return nil, true
	}
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid JSON request body")
		return nil, false
	}
	return body, true
}

func writeResult(h *AbstractHandler, w http.ResponseWriter, result any, err error) {
	if err != nil {
		writeErrorHeaders(w, err)
		var ae *APIError
		if errors.As(err, &ae) {
			h.WriteError(w, ae.Status, http.StatusText(ae.Status), ae.Msg)
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, result)
}
