package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
	"github.com/nauticana/keel/user"
)

// securityHeaderTemplate is built once at package init and copied
// into each response Header on hit (v0.4.5 perf). The previous
// implementation called w.Header().Set six times per request,
// each Set hashing the canonical header name and ranging the
// header map for an existing key — pure overhead for headers that
// never change. maps.Copy walks the source map once and assigns
// directly, avoiding both the canonicalization and the existence
// scan since templates are pre-canonicalized via http.Header.Set
// at init.
var securityHeaderTemplate = func() http.Header {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests")
	h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("X-Frame-Options", "DENY")
	return h
}()

type HttpBackend struct {
	Journal logger.ApplicationLogger
	DB      data.DatabaseRepository
	Secrets secret.SecretProvider

	// Origin is a comma-separated allowlist of permitted CORS origins.
	// "*" allows any origin (NOT compatible with credentialed requests).
	// An empty string disables the CORS middleware entirely. The
	// middleware echoes the inbound `Origin` header back ONLY when it
	// matches one of the allowlist entries; mismatched origins receive
	// no CORS headers. `Vary: Origin` is always set so caches/CDNs key
	// responses correctly per origin.
	Origin string

	// AllowCredentials, when true, sets `Access-Control-Allow-Credentials:
	// true` on responses. Required when the browser must send cookies
	// or Authorization headers cross-origin. Per CORS spec this is
	// incompatible with `Origin: "*"`; a misconfiguration is rejected
	// at startup time inside CORSMiddleware.
	AllowCredentials bool

	UserService   user.UserService
	QuotaService  port.QuotaService
	ApiKeyService *APIKeyService
	handler       http.Handler

	// mux is per-instance so two HttpBackend objects (test fixtures,
	// admin / public split deployments) can coexist in one process
	// without colliding on http.DefaultServeMux's package-global
	// state. Lazily constructed on first Handle (MAJOR 7).
	mux *http.ServeMux

	// regMu serializes Handle's mutation of mux + registered. Handle
	// is documented as idempotent which invites concurrent reloads;
	// without the mutex two simultaneous calls would race the map
	// (Go runtime panic on concurrent map write) AND the package
	// http.ServeMux mutex (handled internally, but still racy on
	// our `registered` companion set).
	regMu sync.Mutex
	// registered tracks which routes Handle has already wired into
	// the per-instance mux. Re-registration would panic; the set
	// makes Handle idempotent (P1-63 / MAJOR 7).
	registered map[string]struct{}

	// CallbackBypass is a function that returns true for paths that should bypass SSO (e.g. OAuth callbacks)
	CallbackBypass func(path string) bool
}

// Handle is idempotent (P1-63 / MAJOR 7).
//
// Routes are wired into a per-instance *http.ServeMux rather than
// http.DefaultServeMux so a process hosting two HttpBackend
// instances (e.g. an admin server alongside the public API) cannot
// have one's routes leak into the other. The first Handle call also
// builds the middleware stack on top of that per-instance mux.
//
// Concurrent calls to Handle are serialized via regMu so a "reload
// my routes" admin path won't race the underlying registered set.
func (h *HttpBackend) Handle(functions map[string]func(w http.ResponseWriter, r *http.Request)) {
	h.regMu.Lock()
	defer h.regMu.Unlock()
	if h.mux == nil {
		h.mux = http.NewServeMux()
	}
	if h.handler == nil {
		h.handler = h.APIKeyMiddleware(h.SSOMiddleware(h.mux))
		if h.Origin != "" {
			h.handler = h.CORSMiddleware(h.handler)
		}
		// PlainHTTPGuard enforces --max_tls_version. When TLS is required,
		// plain-HTTP requests are rejected with 426 Upgrade Required except
		// for /health and /ready (VPC-internal health checkers).
		h.handler = h.PlainHTTPGuard(h.handler)
		// SecurityHeaders wraps the outer chain so hardening headers land on
		// every response, including short-circuited middleware errors.
		h.handler = h.SecurityHeadersMiddleware(h.handler)
	}
	if h.registered == nil {
		h.registered = map[string]struct{}{}
	}
	for path, handler := range functions {
		if _, seen := h.registered[path]; seen {
			continue
		}
		h.mux.HandleFunc(path, handler)
		h.registered[path] = struct{}{}
	}
}

func (h *HttpBackend) Run(ctx context.Context) {
	if h.handler == nil {
		h.Journal.Error("HTTP handlers not initialized")
		return
	}

	// /health is registered via Handle so the middleware stack
	// (SecurityHeaders, PlainHTTPGuard, CORS) wraps it. The /health
	// path is intentionally allow-listed inside SSO and PlainHTTP
	// guards so health checkers can hit it without a JWT or TLS.
	h.Handle(map[string]func(w http.ResponseWriter, r *http.Request){
		"/health": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		},
	})

	// Plain HTTP always binds on HttpApiPort. When a deployment also
	// provides TLSCert/TLSKey, an additional HTTPS listener binds on
	// HTTPSPort (default 443). TLS is opt-in; consumers without cert
	// files keep the existing single-listener behavior.
	//
	// When --max_tls_version != "none", the TLS listener enforces
	// MinVersion via tls.Config and the plain-HTTP listener rejects
	// non-health requests (see PlainHTTPGuard). If the policy requires
	// TLS but no cert is configured, fail fast — a mis-provisioned prod
	// deploy would otherwise accept zero traffic silently.
	policy := resolveTLSPolicy()
	if policy.enforce && (*common.TLSCert == "" || *common.TLSKey == "") {
		h.Journal.Fatal(fmt.Sprintf("--max_tls_version=%s requires --tls_cert and --tls_key", *common.MaxTLSVersion))
		return
	}

	newServer := func(port int) *http.Server {
		return &http.Server{
			Addr:         fmt.Sprintf(":%d", port),
			Handler:      h.handler,
			ReadTimeout:  time.Duration(*common.HttpReadTimeout) * time.Second,
			WriteTimeout: time.Duration(*common.HttpWriteTimeout) * time.Second,
			IdleTimeout:  time.Duration(*common.HttpIdleTimeout) * time.Second,
		}
	}

	// listenFail signals a bind/serve error from either listener so
	// Run can exit cleanly instead of waiting on the signal channel
	// forever (P1-69). A misconfigured port (already-bound, or no
	// permission for <1024) used to silently log + hang.
	listenFail := make(chan error, 2)

	plainServer := newServer(*common.HttpApiPort)
	h.Journal.Info(fmt.Sprintf("starting http server on port %d (tls_policy=%s)", *common.HttpApiPort, *common.MaxTLSVersion))
	go func() {
		if err := plainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			h.Journal.Error("http listener: " + err.Error())
			listenFail <- err
		}
	}()

	var tlsServer *http.Server
	if *common.TLSCert != "" && *common.TLSKey != "" {
		tlsServer = newServer(*common.HTTPSPort)
		if policy.enforce {
			tlsServer.TLSConfig = &tls.Config{MinVersion: policy.minVersion}
		}
		h.Journal.Info(fmt.Sprintf("starting https server on port %d", *common.HTTPSPort))
		go func() {
			if err := tlsServer.ListenAndServeTLS(*common.TLSCert, *common.TLSKey); err != nil && err != http.ErrServerClosed {
				h.Journal.Error("tls listener: " + err.Error())
				listenFail <- err
			}
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-quit:
		// graceful shutdown below
	case err := <-listenFail:
		h.Journal.Error("listener failed at startup: " + err.Error())
		// Drain any second listener failure so it doesn't disappear
		// silently — the surviving select branch only consumes one.
		select {
		case err2 := <-listenFail:
			h.Journal.Error("second listener failed at startup: " + err2.Error())
		default:
		}
		// Fall through to shutdown so the surviving listener (if any)
		// also closes cleanly.
	}

	h.Journal.Info("shutting down server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := plainServer.Shutdown(shutdownCtx); err != nil {
		h.Journal.Error(fmt.Sprintf("http server forced to shutdown: %s", err.Error()))
	}
	if tlsServer != nil {
		if err := tlsServer.Shutdown(shutdownCtx); err != nil {
			h.Journal.Error(fmt.Sprintf("tls server forced to shutdown: %s", err.Error()))
		}
	}
}

// CORSMiddleware applies CORS headers driven by HttpBackend.Origin, an
// allowlist of comma-separated origins (or the wildcard "*").
//
// Key correctness properties:
//
//   - The browser-supplied `Origin` request header is matched against
//     the allowlist BEFORE any CORS response header is set. Mismatched
//     origins receive no Access-Control-Allow-Origin and the response
//     proceeds normally (browsers will then refuse cross-origin reads
//     in the client). The pre-v0.5 implementation echoed the static
//     configured value regardless of which origin actually called,
//     which let downstream caches poison responses across origins.
//
//   - `Vary: Origin` is always set so HTTP caches / CDNs use the
//     request Origin as part of the cache key. Without this header a
//     cached preflight response from origin A could be served back to
//     origin B.
//
//   - When AllowCredentials is true, the wildcard "*" is rejected at
//     request time (per CORS spec, credentialed responses must echo
//     a single concrete origin). Operators wiring credentials with a
//     wildcard get a startup-time warning to the journal and CORS is
//     disabled — fail closed.
func (h *HttpBackend) CORSMiddleware(next http.Handler) http.Handler {
	allowed := parseCORSAllowlist(h.Origin)
	wildcard := containsString(allowed, "*")
	if h.AllowCredentials && wildcard {
		// Misconfiguration: spec violation, browser will refuse the
		// response anyway. Log once and disable CORS so the rest of
		// the chain still functions.
		if h.Journal != nil {
			h.Journal.Error("CORS: AllowCredentials + Origin=\"*\" is invalid; CORS disabled")
		}
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vary: Origin must be set on every response so caches don't
		// reuse a CORS-keyed entry for a different origin.
		w.Header().Add("Vary", "Origin")
		reqOrigin := r.Header.Get("Origin")
		allow := ""
		if wildcard && !h.AllowCredentials {
			allow = "*"
		} else if reqOrigin != "" && containsString(allowed, reqOrigin) {
			allow = reqOrigin
		}
		if allow != "" {
			w.Header().Set("Access-Control-Allow-Origin", allow)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			// Cache preflight for 10 minutes (P1-66). Browsers re-issue
			// OPTIONS on every CORS request without a Max-Age, doubling
			// our ingress traffic for any cross-origin app.
			w.Header().Set("Access-Control-Max-Age", "600")
			if h.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// parseCORSAllowlist splits HttpBackend.Origin on commas and trims
// whitespace. Empty entries are dropped.
func parseCORSAllowlist(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func containsString(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

// tlsPolicy is the parsed view of --max_tls_version.
type tlsPolicy struct {
	enforce    bool   // true when TLS is required (flag != "none")
	minVersion uint16 // tls.VersionTLS10 .. tls.VersionTLS13; zero when !enforce
}

// resolveTLSPolicy parses the --max_tls_version flag. Unknown values
// fall back to "none" with a one-time warning logged by the caller.
func resolveTLSPolicy() tlsPolicy {
	switch strings.ToLower(*common.MaxTLSVersion) {
	case "tls10":
		return tlsPolicy{enforce: true, minVersion: tls.VersionTLS10}
	case "tls11":
		return tlsPolicy{enforce: true, minVersion: tls.VersionTLS11}
	case "tls12":
		return tlsPolicy{enforce: true, minVersion: tls.VersionTLS12}
	case "tls13":
		return tlsPolicy{enforce: true, minVersion: tls.VersionTLS13}
	default:
		return tlsPolicy{enforce: false}
	}
}

// PlainHTTPGuard enforces --max_tls_version on the plain-HTTP listener.
// When TLS is required, non-TLS requests get 426 Upgrade Required unless
// the path is /health or /ready (which are VPC-scoped health endpoints
// intentionally left reachable without TLS). When TLS is not required
// (default), the guard is a pass-through.
func (h *HttpBackend) PlainHTTPGuard(next http.Handler) http.Handler {
	policy := resolveTLSPolicy()
	if !policy.enforce {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Upgrade", "TLS/1.2, HTTP/1.1")
		http.Error(w, `{"error":"HTTPS required"}`, http.StatusUpgradeRequired)
	})
}

// SecurityHeadersMiddleware sets hardening headers on every response.
//
//   - Strict-Transport-Security: pins browsers to HTTPS for this origin.
//     Per RFC 6797 browsers ignore the header when received over plain
//     HTTP, so setting it unconditionally is safe. No `preload` directive —
//     adding a domain to the HSTS preload list is a long-term commitment
//     that can't be rolled back quickly; opt in manually via the
//     hstspreload.org form when ready.
//   - Content-Security-Policy: a JSON-API-tuned policy that disables
//     every browser-side execution surface (default-src 'none', no
//     script / style / img / frame / connect / form / base) plus
//     upgrade-insecure-requests. Browsers that fetch a JSON response
//     directly will never use the CSP, but error pages / accidental
//     HTML responses (e.g. an unhandled panic page from a misconfigured
//     reverse proxy) get locked down. Consumers serving HTML behind
//     this middleware MUST replace the policy — see
//     SetSecurityHeader / wrap with their own middleware. (P2-21.)
//   - Permissions-Policy: refuses every powerful browser API by
//     default — geolocation, camera, microphone, payment, USB,
//     accelerometer, fullscreen, etc. JSON APIs never need them, and
//     a misconfigured response leaking permission grants is the same
//     class of risk as the CSP gap above. (P2-21.)
//   - X-Content-Type-Options: nosniff — prevents MIME sniffing.
//   - Referrer-Policy: strict-origin-when-cross-origin — limits how much
//     of the URL leaks to third-party origins on cross-origin navigations.
//   - X-Frame-Options: DENY — refuses to be rendered in an iframe;
//     clickjacking protection. API responses don't render in frames, so
//     this is belt-and-braces for error pages / HTML responses.
func (h *HttpBackend) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		maps.Copy(w.Header(), securityHeaderTemplate)
		next.ServeHTTP(w, r)
	})
}

// SSOMiddleware gates RestPrefix routes with a JWT bearer-token check.
//
// Status-code corrections (P1-65):
//   - "no auth header" / "bad token" → 401 with WWW-Authenticate.
//     Per RFC 7235, 401 is "no/invalid credentials"; the previous
//     403 was "credentials accepted but not authorized" — wrong
//     for these cases and confusing for OAuth-style clients.
//   - PartnerId == 0 (unassigned) is also unauthorized; the old <0
//     check accepted partnerId=0 silently.
//
// Bearer-prefix matching is case-insensitive per RFC 7235; a client
// sending "bearer <tok>" should not be rejected just on case.
func (h *HttpBackend) SSOMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, common.RestPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		// Allow project-specific callback bypasses (e.g. OAuth callbacks)
		if h.CallbackBypass != nil && h.CallbackBypass(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		authHeader := r.Header.Get("Authorization")
		bearer := ""
		if len(authHeader) >= 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
			bearer = strings.TrimSpace(authHeader[7:])
		}
		if bearer == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="keel"`)
			http.Error(w, "Missing authentication header", http.StatusUnauthorized)
			return
		}
		session, err := h.UserService.ParseJWT(bearer)
		if err != nil {
			// Avoid logging an entry per failed login attempt — a
			// brute-force attempt would otherwise flood the journal.
			// Tests / dev still see the diagnostic via debug-level
			// logging if the consumer wires that up.
			w.Header().Set("WWW-Authenticate", `Bearer realm="keel", error="invalid_token"`)
			http.Error(w, "Invalid authentication token", http.StatusUnauthorized)
			return
		}
		if session.PartnerId <= 0 {
			http.Error(w, "User account is not associated with a business partner", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// APIKeyMiddleware gates /pubapi/* routes with the shared APIKeyAuthMiddleware
// factory. Non-/pubapi/* requests pass through unauthenticated (JWT auth via
// SSOMiddleware handles those). Standalone keel-using services that want
// auth on every request (e.g. an MCP server) call APIKeyAuthMiddleware
// directly instead of going through HttpBackend.
func (h *HttpBackend) APIKeyMiddleware(next http.Handler) http.Handler {
	authed := APIKeyAuthMiddleware(h.ApiKeyService, h.QuotaService, h.Journal)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, common.PubapiPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		authed.ServeHTTP(w, r)
	})
}
