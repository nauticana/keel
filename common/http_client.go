package common

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// DefaultOutboundTimeout caps a single outbound request lifecycle —
// dial + TLS + send + receive headers + receive body. 30s is generous
// for nearly any third-party API keel talks to (Stripe, Twilio,
// Google JWKs, FCM, GCS / S3 / Azure metadata) while still preventing
// a hung peer from holding a goroutine indefinitely.
const DefaultOutboundTimeout = 30 * time.Second

// outboundClient is a process-wide *http.Client used for every keel
// outbound HTTP call that doesn't have a more specific reason to
// build its own. Constructed exactly once via outboundOnce.
var (
	outboundOnce   sync.Once
	outboundClient *http.Client
)

// HTTPClient returns the shared outbound *http.Client. Use this for
// every keel-internal third-party request — Stripe, Google JWKs,
// Apple JWKs, Twilio, mail-API, etc. — so timeout, transport pool
// settings, and (eventually) tracing instrumentation are uniform.
//
// Adapters that need a special transport (e.g. mTLS to a private
// CA, or a non-default redirect policy) build their own *http.Client
// directly; HTTPClient is for the common case.
//
// Construction is gated by sync.Once (v0.4.4 perf cluster). The
// previous lazy init was racy: two concurrent first-callers each
// allocated a *http.Client; the loser's instance leaked. Today
// that's harmless because both clients share http.DefaultTransport,
// but a future change that customizes Transport here would silently
// drop the customization on whichever client lost the race.
func HTTPClient() *http.Client {
	outboundOnce.Do(func() {
		transport := http.DefaultTransport
		if *OutboundMaxRPS > 0 {
			transport = &rateLimitedTransport{
				base:    http.DefaultTransport,
				limiter: rate.NewLimiter(rate.Limit(*OutboundMaxRPS), burstFor(*OutboundMaxRPS)),
			}
		}
		outboundClient = &http.Client{
			Timeout:       DefaultOutboundTimeout,
			Transport:     transport,
			CheckRedirect: checkRedirect,
		}
	})
	return outboundClient
}

// checkRedirect caps redirect following and fails fast on a same-URL loop, so a
// misbehaving peer can't bounce the client around forever.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= *OutboundMaxRedirects {
		return fmt.Errorf("outbound: stopped after %d redirects (loop guard)", *OutboundMaxRedirects)
	}
	for _, prev := range via {
		if prev.URL.String() == req.URL.String() {
			return fmt.Errorf("outbound: redirect loop detected at %s", req.URL.String())
		}
	}
	return nil
}

// rateLimitedTransport throttles the shared client to --outbound_max_rps so a
// runaway outbound loop is capped instead of draining edge/CDN quota. Wait
// respects the request context (and thus the client timeout).
type rateLimitedTransport struct {
	base    http.RoundTripper
	limiter *rate.Limiter
}

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.Wait(req.Context()); err != nil {
		return nil, fmt.Errorf("outbound: rate limit wait: %w", err)
	}
	return t.base.RoundTrip(req)
}

func burstFor(rps float64) int {
	if rps < 1 {
		return 1
	}
	return int(rps) * 2
}
