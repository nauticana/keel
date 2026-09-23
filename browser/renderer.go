package browser

import (
	"context"
	"net/http"
	"time"
)

const DefaultRenderTimeout = 30 * time.Second

type RenderRequest struct {
	URL       string
	Timeout   time.Duration // 0 = DefaultRenderTimeout
	UserAgent string        // empty = Chrome's own
	// Evaluations maps a caller-chosen label to a JS expression run against the
	// loaded DOM; its JSON value lands under the same label in the result.
	Evaluations    map[string]string
	CaptureCookies bool
	// CaptureRequests records every request the page sends, in order, up to
	// MaxRequests (0 = DefaultMaxRequests). Bodies are never recorded.
	CaptureRequests bool
	MaxRequests     int
	// Settle waits after load, before anything is captured, for work the page
	// defers past load — a tag that beacons late. It counts against Timeout.
	Settle time.Duration
}

type RenderResult struct {
	URL          string
	RenderedHTML string
	// Evaluations holds json.Unmarshal-typed values. An expression that throws
	// evaluates to nil; one that could not run at all is in EvaluationErrors.
	Evaluations      map[string]any
	EvaluationErrors map[string]error
	Cookies          []http.Cookie
	Requests         []NetworkRequest
	// RequestsTruncated: MaxRequests was reached and later requests are missing.
	RequestsTruncated bool
	Loaded            time.Duration // navigate until body is visible
}

// Truthy reports whether the labelled evaluation produced a JS-truthy value;
// a missing label is false.
func (r *RenderResult) Truthy(label string) bool {
	switch v := r.Evaluations[label].(type) {
	case nil:
		return false
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v != ""
	default:
		return true
	}
}

// Renderer loads a page in a real browser and reports on the resulting DOM.
type Renderer interface {
	Render(ctx context.Context, req RenderRequest) (*RenderResult, error)
}
