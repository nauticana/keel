package common

import (
	"net/http"
	"sync"
	"time"
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
		outboundClient = &http.Client{
			Timeout: DefaultOutboundTimeout,
		}
	})
	return outboundClient
}
