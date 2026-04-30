package handler

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/payment"
)

// MaxWebhookBodyBytes caps the size of an incoming webhook payload to
// protect against oversized inputs. Stripe's largest events sit well
// below 256 KiB.
const MaxWebhookBodyBytes = 1 << 18 // 256 KiB

// AbstractPaymentHandler is the base HTTP handler for webhook endpoints.
// Each webhook route (`/public/webhook/stripe`, etc.) is a thin wrapper
// around Process() that knows which provider it's for.
//
// CreateCheckout-specific configuration:
//   - AllowedRedirectHosts whitelists hostnames that may appear in
//     SuccessURL / CancelURL. An empty slice rejects all redirects so
//     nothing leaks until the consumer wires the list. Stripe forwards
//     the user to whatever URL we hand it; without a whitelist this is
//     an open-redirect vector after a successful checkout.
//   - AllowedPriceIDs whitelists Stripe price ids the caller may use.
//     An attacker without this gate could pick a $0 trial price for a
//     paid plan. Empty = allow none (handler returns 400).
//   - AllowGuestCheckout, when true, drops the JWT requirement on
//     /api/billing/checkout. The DEFAULT is false (zero-value bool),
//     so a struct-literal-constructed AbstractPaymentHandler enforces
//     auth out of the box. Pre-v0.5 this was inverted as
//     RequireAuthForCheckout where the documented default ("true")
//     conflicted with Go's zero-value, silently disabling auth on
//     handlers built via positional struct literals.
type AbstractPaymentHandler struct {
	AbstractHandler
	Processor *payment.WebhookProcessor
	Handler   payment.PaymentEventHandler
	Checkout  payment.CheckoutClient
	Journal   logger.ApplicationLogger

	AllowedRedirectHosts []string
	AllowedPriceIDs      []string
	AllowGuestCheckout   bool
}

// HandleWebhook processes a webhook for the named provider.
// Mount as many methods as needed (HandleStripeWebhook, HandleLemonSqueezyWebhook)
// or call HandleWebhook directly from a custom route.
func (h *AbstractPaymentHandler) HandleWebhook(providerName string, w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	provider := h.Processor.Provider(providerName)
	if provider == nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "unknown payment provider")
		return
	}

	// Webhook-specific 256 KiB cap (smaller than the global *common.MaxRequestSize
	// 16MB used by AbstractHandler.ReadRequest). Provider webhooks are tiny;
	// a tighter cap protects against malicious large bodies before signature
	// verification has a chance to fail. Stays bespoke for that reason.
	r.Body = http.MaxBytesReader(w, r.Body, MaxWebhookBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "failed to read body")
		return
	}

	sigHeader := r.Header.Get(provider.SignatureHeader())

	if err := h.Processor.Process(r.Context(), providerName, sigHeader, body, h.Handler); err != nil {
		// Log the full diagnostic server-side; clients only see a
		// generic message so we never leak signature internals or DB
		// errors. Map the error class to a status the provider's
		// retry policy understands:
		//   - Permanent (bad signature, malformed body, unknown
		//     provider) → 400. Stripe / LemonSqueezy treat that as
		//     "give up, this delivery is bad" and stop retrying.
		//   - Transient (handler / DB / network) → 500. The provider
		//     re-delivers on its standard backoff schedule.
		h.logError("webhook %s: %v", providerName, err)
		if errors.Is(err, payment.ErrPermanent) {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "webhook rejected")
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "webhook processing failed")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// HandleStripeWebhook is a convenience wrapper pinned to the "stripe" provider.
func (h *AbstractPaymentHandler) HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	h.HandleWebhook("stripe", w, r)
}

// HandleLemonSqueezyWebhook is a convenience wrapper pinned to the "lemonsqueezy" provider.
func (h *AbstractPaymentHandler) HandleLemonSqueezyWebhook(w http.ResponseWriter, r *http.Request) {
	h.HandleWebhook("lemonsqueezy", w, r)
}

// CreateCheckoutRequest is the JSON body accepted by CreateCheckout.
type CreateCheckoutRequest struct {
	Mode       string            `json:"mode"`
	PriceID    string            `json:"priceId"`
	Quantity   int64             `json:"quantity"`
	Email      string            `json:"email"`
	SuccessURL string            `json:"successUrl"`
	CancelURL  string            `json:"cancelUrl"`
	Metadata   map[string]string `json:"metadata"`
}

// CreateCheckout exposes CheckoutClient.CreateCheckoutSession as an HTTP
// endpoint. Mounted at /api/billing/checkout by convention.
//
// Defenses (vs the original "wrap it in your own middleware" posture):
//   - JWT requirement is on by default. A guest-checkout integration
//     must opt in via AllowGuestCheckout=true.
//   - 64 KiB body cap via MaxBytesReader inside ReadRequest. Without
//     this, an unauthenticated CreateCheckout (when guest-checkout is
//     enabled) is a JSON-bomb DoS vector.
//   - SuccessURL and CancelURL must match AllowedRedirectHosts. Stripe
//     happily forwards users to any URL we hand it; without a host
//     allowlist, an attacker can craft an open redirect by abusing
//     this endpoint.
//   - For mode="subscription" / "payment", PriceID must be in
//     AllowedPriceIDs. Otherwise an attacker can ask for checkout
//     against an unrelated, lower-priced SKU on the same Stripe
//     account. mode="setup" (Stripe SetupIntent — capture a payment
//     method without charging) has no price by design and the price
//     check is skipped; a non-empty PriceID in setup mode is rejected
//     since Stripe ignores line_items there anyway.
//   - Mode is restricted to the three values port.CheckoutRequest
//     documents ("subscription" | "payment" | "setup"). Empty mode
//     defaults to "subscription" to preserve the v0.4.x behavior.
//   - Stripe / provider error bodies never reach the client; they're
//     logged server-side and the caller sees a generic 502.
func (h *AbstractPaymentHandler) CreateCheckout(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	if h.Checkout == nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "checkout client not configured")
		return
	}
	if !h.AllowGuestCheckout {
		if _, ok := h.RequireUser(w, r); !ok {
			return
		}
	}
	var req CreateCheckoutRequest
	if !h.ReadRequest(w, r, &req) {
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = "subscription"
	}
	switch mode {
	case "subscription", "payment":
		if !h.priceAllowed(req.PriceID) {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "priceId is not allowed")
			return
		}
	case "setup":
		// Stripe ignores line_items in setup mode, so any non-empty
		// priceId here is a caller mistake. Reject up front so the
		// error is crisp instead of a 502 from a downstream Stripe
		// 400.
		if req.PriceID != "" {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "priceId is not allowed in setup mode")
			return
		}
	default:
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "mode must be subscription, payment, or setup")
		return
	}
	if !h.redirectAllowed(req.SuccessURL) {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "successUrl is not allowed")
		return
	}
	if !h.redirectAllowed(req.CancelURL) {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "cancelUrl is not allowed")
		return
	}
	url, err := h.Checkout.CreateCheckoutSession(r.Context(), payment.CheckoutRequest{
		Mode:       mode,
		PriceID:    req.PriceID,
		Quantity:   req.Quantity,
		Email:      req.Email,
		SuccessURL: req.SuccessURL,
		CancelURL:  req.CancelURL,
		Metadata:   req.Metadata,
	})
	if err != nil {
		// Stripe's raw error body sometimes reveals account / price-id
		// internals — keep that to the journal, not the response.
		h.logError("checkout: %v", err)
		h.WriteError(w, http.StatusBadGateway, "Bad Gateway", "checkout session failed")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"checkoutUrl": url})
}

// priceAllowed reports whether priceID is in the configured allowlist.
// An empty allowlist is treated as "explicitly disabled" so a default-
// constructed handler can never accept an attacker-controlled priceId.
func (h *AbstractPaymentHandler) priceAllowed(priceID string) bool {
	if priceID == "" {
		return false
	}
	for _, p := range h.AllowedPriceIDs {
		if p == priceID {
			return true
		}
	}
	return false
}

// redirectAllowed parses the URL and checks its host against the
// AllowedRedirectHosts list. URLs without a scheme (relative paths) are
// rejected because Stripe requires absolute URLs and an unschemed
// string cannot be checked for safety.
//
// Matching rules:
//   - An entry without a colon is a hostname and matches the parsed
//     URL's hostname, port-insensitively. So "app.example" matches
//     both "https://app.example/" and "https://app.example:8443/".
//   - An entry containing a colon (e.g. "app.example:8443") is
//     port-strict — it matches only that exact host:port. Use this
//     when you intentionally want to gate by port.
//
// Pre-v0.4.7 behavior compared against `parsed.Host` (the host:port
// pair), which silently rejected legitimate non-default-port URLs
// when the operator listed only the hostname. The new rules cover
// both intents: hostname-only entries are port-tolerant; operators
// who listed `host:port` explicitly still get exact-match.
func (h *AbstractPaymentHandler) redirectAllowed(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return false
	}
	hostname := parsed.Hostname()
	hostport := parsed.Host
	for _, entry := range h.AllowedRedirectHosts {
		if strings.ContainsRune(entry, ':') {
			if strings.EqualFold(entry, hostport) {
				return true
			}
			continue
		}
		if strings.EqualFold(entry, hostname) {
			return true
		}
	}
	return false
}

func (h *AbstractPaymentHandler) logError(format string, args ...any) {
	if h.Journal != nil {
		h.Journal.Error(fmt.Sprintf(format, args...))
	}
}
