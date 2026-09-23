package browser

import (
	"slices"
	"sync"

	"github.com/chromedp/cdproto/network"
)

const DefaultMaxRequests = 1000

// NetworkRequest is one request the page sent; each redirect hop is its own
// entry. A cross-origin iframe runs in its own renderer, so its requests are
// not seen.
type NetworkRequest struct {
	URL    string
	Method string
	Type   string // Chrome's resource type: Document, Script, XHR, Fetch, Image, Ping, …
	Status int    // 0 when unanswered: failed (see Error) or still pending at capture
	Error  string // Chrome's reason for giving up, e.g. net::ERR_BLOCKED_BY_CLIENT
}

// requestLog collects network events, which chromedp delivers on its own goroutine.
type requestLog struct {
	mu        sync.Mutex
	max       int
	requests  []NetworkRequest
	byID      map[network.RequestID]int // latest hop of each request
	truncated bool
}

func newRequestLog(max int) *requestLog {
	if max <= 0 {
		max = DefaultMaxRequests
	}
	return &requestLog{max: max, byID: map[network.RequestID]int{}}
}

func (l *requestLog) observe(ev any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch ev := ev.(type) {
	case *network.EventRequestWillBeSent:
		if ev.Request == nil {
			return
		}
		if ev.RedirectResponse != nil {
			l.answer(ev.RequestID, ev.RedirectResponse)
		}
		delete(l.byID, ev.RequestID)
		if len(l.requests) >= l.max {
			l.truncated = true
			return
		}
		l.byID[ev.RequestID] = len(l.requests)
		l.requests = append(l.requests, NetworkRequest{URL: ev.Request.URL, Method: ev.Request.Method, Type: string(ev.Type)})
	case *network.EventResponseReceived:
		l.answer(ev.RequestID, ev.Response)
	case *network.EventLoadingFailed:
		if i, ok := l.byID[ev.RequestID]; ok {
			l.requests[i].Error = ev.ErrorText
		}
	}
}

func (l *requestLog) answer(id network.RequestID, resp *network.Response) {
	if i, ok := l.byID[id]; ok && resp != nil {
		l.requests[i].Status = int(resp.Status)
	}
}

func (l *requestLog) snapshot() ([]NetworkRequest, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.requests), l.truncated
}
