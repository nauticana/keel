package browser

import (
	"context"
	"iter"
	"slices"
	"sync"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
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

// requestLog collects network events. Each event type arrives on its own
// goroutine, unordered against the others, so final outcomes are kept per
// request and joined to its latest hop at snapshot.
type requestLog struct {
	mu        sync.Mutex
	max       int
	requests  []NetworkRequest
	byID      map[network.RequestID]int // latest hop of each request
	outcomes  map[network.RequestID]NetworkRequest
	truncated bool
}

func newRequestLog(max int) *requestLog {
	if max <= 0 {
		max = DefaultMaxRequests
	}
	return &requestLog{max: max, byID: map[network.RequestID]int{}, outcomes: map[network.RequestID]NetworkRequest{}}
}

// listen records the tab's network events until the tab closes.
func (l *requestLog) listen(tabCtx context.Context) {
	go l.consume(chromedp.Events(tabCtx, network.RequestWillBeSent), l.sent)
	go l.consume(chromedp.Events(tabCtx, network.ResponseReceived), func(ev network.EventResponseReceived) {
		if ev.Response != nil {
			l.settle(ev.RequestID, func(o *NetworkRequest) { o.Status = int(ev.Response.Status) })
		}
	})
	go l.consume(chromedp.Events(tabCtx, network.LoadingFailed), func(ev network.EventLoadingFailed) {
		l.settle(ev.RequestID, func(o *NetworkRequest) { o.Error = ev.ErrorText })
	})
}

func (l *requestLog) consume[E any](events iter.Seq2[E, error], handle func(E)) {
	for ev, err := range events {
		if err != nil {
			return
		}
		handle(ev)
	}
}

func (l *requestLog) sent(ev network.EventRequestWillBeSent) {
	if ev.Request == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if i, ok := l.byID[ev.RequestID]; ok && ev.RedirectResponse != nil {
		l.requests[i].Status = int(ev.RedirectResponse.Status)
	}
	delete(l.byID, ev.RequestID)
	if len(l.requests) >= l.max {
		l.truncated = true
		return
	}
	l.byID[ev.RequestID] = len(l.requests)
	l.requests = append(l.requests, NetworkRequest{URL: ev.Request.URL, Method: ev.Request.Method, Type: string(ev.Type)})
}

// settle records an outcome; one that may precede its request is kept only
// while the outcomes stay within twice the request cap.
func (l *requestLog) settle(id network.RequestID, set func(*NetworkRequest)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	o, ok := l.outcomes[id]
	if _, known := l.byID[id]; !ok && !known && len(l.outcomes) >= 2*l.max {
		return
	}
	set(&o)
	l.outcomes[id] = o
}

func (l *requestLog) snapshot() ([]NetworkRequest, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := slices.Clone(l.requests)
	for id, i := range l.byID {
		if o, ok := l.outcomes[id]; ok {
			if o.Status != 0 {
				out[i].Status = o.Status
			}
			out[i].Error = o.Error
		}
	}
	return out, l.truncated
}
