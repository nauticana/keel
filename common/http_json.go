package common

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/nauticana/keel/config"
)

// HTTPStatusError is a non-2xx response from RequestJSON, kept typed so callers
// can map it to their own provider errors.
type HTTPStatusError struct {
	Status int
	Body   string
	Header http.Header
}

const statusErrorBodyPreview = 512

// Error carries a bounded preview; the full response is in Body.
func (e *HTTPStatusError) Error() string {
	if len(e.Body) > statusErrorBodyPreview {
		return fmt.Sprintf("http status %d: %s… (%d bytes)", e.Status, e.Body[:statusErrorBodyPreview], len(e.Body))
	}
	return fmt.Sprintf("http status %d: %s", e.Status, e.Body)
}

// Unauthorized: credentials are missing, expired or lack scope (401, 403).
func (e *HTTPStatusError) Unauthorized() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

func (e *HTTPStatusError) RateLimited() bool { return e.Status == http.StatusTooManyRequests }

// Transient: a retry may succeed (408, 425, 429, 5xx).
func (e *HTTPStatusError) Transient() bool {
	switch e.Status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	}
	return e.Status >= 500
}

// Permanent: the same request will keep failing (every other non-2xx, including 3xx).
func (e *HTTPStatusError) Permanent() bool { return !e.Transient() }

// HTTPStatus returns the status carried by err, or 0 when err holds no HTTPStatusError.
func HTTPStatus(err error) int {
	var se *HTTPStatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// ErrResponseTooLarge means the response body exceeded outbound_max_response_size.
var ErrResponseTooLarge = errors.New("outbound: response body exceeds outbound_max_response_size")

// RequestJSON sends payload (when non-nil) as a JSON body on the shared client
// and returns the response body and headers. A non-2xx response returns both
// alongside an *HTTPStatusError.
func RequestJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, http.Header, error) {
	return requestJSON(ctx, HTTPClient(), method, url, headers, payload)
}

func requestJSON(ctx context.Context, client *http.Client, method, url string, headers map[string]string, payload any) ([]byte, http.Header, error) {
	limit := config.Config().OutboundMaxResponseSize
	if limit <= 0 {
		return nil, nil, fmt.Errorf("outbound_max_response_size must be positive (got %d)", limit)
	}
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, resp.Header, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(respBody)) > limit {
		respBody = respBody[:limit]
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			statusErr := &HTTPStatusError{Status: resp.StatusCode, Body: string(respBody), Header: resp.Header}
			return respBody, resp.Header, errors.Join(statusErr, ErrResponseTooLarge)
		}
		return respBody, resp.Header, ErrResponseTooLarge
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return respBody, resp.Header, &HTTPStatusError{Status: resp.StatusCode, Body: string(respBody), Header: resp.Header}
	}
	return respBody, resp.Header, nil
}
