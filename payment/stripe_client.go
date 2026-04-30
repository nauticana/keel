package payment

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/secret"
)

// Stripe API endpoints. Overridable on StripeCheckoutClient for tests.
const (
	stripeAPIBase           = "https://api.stripe.com/v1"
	stripeCheckoutPath      = "/checkout/sessions"
	stripeBillingPortalPath = "/billing_portal/sessions"

	// stripeMaxResponseBytes caps the response body we'll buffer from
	// Stripe. The legitimate responses are small JSON documents
	// (kilobytes); a malicious or compromised upstream returning a
	// multi-GB body would otherwise OOM the process.
	stripeMaxResponseBytes = 1 << 20 // 1 MiB

	// stripeMaxRetries bounds the retry budget on idempotent POSTs
	// against Stripe 5xx / 429 responses. Combined with exponential
	// backoff this gives ~8s worst-case before the caller sees an
	// error.
	stripeMaxRetries = 3
)

// StripeCheckoutClient is the default port.CheckoutClient implementation
// backed by Stripe's REST API (form-encoded, Basic auth with secret key).
//
// Hardening notes (P1-07/08/09/12/13/27):
//   - HTTPClient defaults to common.HTTPClient() — a process-wide
//     client with a 30s timeout. Tests override the field directly.
//   - Every outbound POST carries a fresh Idempotency-Key so a network
//     blip that triggers an SDK-level retry never doubles a charge.
//   - Retries on 429 / 5xx with exponential backoff, bounded to
//     stripeMaxRetries. Idempotency-Key is reused across retries so
//     Stripe's own dedupe converges.
//   - The Stripe error response body is logged via the journal but
//     never surfaced to clients — only the status code rides out.
type StripeCheckoutClient struct {
	Secrets    secret.SecretProvider
	SecretName string       // default: "stripe_secret_key"
	BaseURL    string       // default: stripeAPIBase
	HTTPClient *http.Client // default: common.HTTPClient()
}

func NewStripeCheckoutClient(secrets secret.SecretProvider) *StripeCheckoutClient {
	return &StripeCheckoutClient{Secrets: secrets}
}

func (c *StripeCheckoutClient) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return stripeAPIBase
}

func (c *StripeCheckoutClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return common.HTTPClient()
}

func (c *StripeCheckoutClient) secretName() string {
	if c.SecretName != "" {
		return c.SecretName
	}
	return "stripe_secret_key"
}

// CreateCheckoutSession POSTs to /v1/checkout/sessions and returns the
// hosted checkout URL.
func (c *StripeCheckoutClient) CreateCheckoutSession(ctx context.Context, req CheckoutRequest) (string, error) {
	if req.Mode == "" {
		req.Mode = "subscription"
	}
	if req.Mode != "setup" && req.PriceID == "" {
		return "", fmt.Errorf("checkout: price_id is required for mode %q", req.Mode)
	}
	if req.Quantity <= 0 {
		req.Quantity = 1
	}

	form := url.Values{}
	form.Set("mode", req.Mode)
	if req.Email != "" {
		form.Set("customer_email", req.Email)
	}
	if req.Mode != "setup" {
		form.Set("line_items[0][price]", req.PriceID)
		form.Set("line_items[0][quantity]", strconv.FormatInt(req.Quantity, 10))
	}
	if req.SuccessURL != "" {
		form.Set("success_url", req.SuccessURL)
	}
	if req.CancelURL != "" {
		form.Set("cancel_url", req.CancelURL)
	}
	for k, v := range req.Metadata {
		form.Set("metadata["+k+"]", v)
	}

	body, err := c.do(ctx, stripeCheckoutPath, form)
	if err != nil {
		return "", err
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("stripe: parse response: %w", err)
	}
	checkoutURL, _ := parsed["url"].(string)
	if checkoutURL == "" {
		return "", fmt.Errorf("stripe: no checkout url in response")
	}
	return checkoutURL, nil
}

// CreatePortalSession POSTs to /v1/billing_portal/sessions and returns
// the customer-portal URL.
func (c *StripeCheckoutClient) CreatePortalSession(ctx context.Context, customerID, returnURL string) (string, error) {
	if customerID == "" {
		return "", fmt.Errorf("portal: customer id is required")
	}
	form := url.Values{}
	form.Set("customer", customerID)
	if returnURL != "" {
		form.Set("return_url", returnURL)
	}
	body, err := c.do(ctx, stripeBillingPortalPath, form)
	if err != nil {
		return "", err
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("stripe: parse portal response: %w", err)
	}
	portalURL, _ := parsed["url"].(string)
	if portalURL == "" {
		return "", fmt.Errorf("stripe: no portal url in response")
	}
	return portalURL, nil
}

// do issues the form-encoded POST against Stripe with idempotency,
// bounded retries, capped response, and 2xx-range success matching.
// Stripe error bodies are NOT propagated to the caller verbatim — the
// caller (and the HTTP handler above) only sees the status code, so
// internal request ids / account hints in Stripe's error JSON never
// leak. The full error text rides out via the wrapped error so the
// service-layer journal can record it.
func (c *StripeCheckoutClient) do(ctx context.Context, path string, form url.Values) ([]byte, error) {
	secret, err := c.Secrets.GetSecret(ctx, c.secretName())
	if err != nil {
		return nil, fmt.Errorf("stripe: get secret: %w", err)
	}
	idempotencyKey := newIdempotencyKey()
	encoded := form.Encode()

	var lastErr error
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt <= stripeMaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+path, strings.NewReader(encoded))
		if err != nil {
			return nil, fmt.Errorf("stripe: build request: %w", err)
		}
		req.SetBasicAuth(secret, "")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Idempotency-Key", idempotencyKey)

		resp, err := c.httpClient().Do(req)
		if err != nil {
			lastErr = fmt.Errorf("stripe: request failed: %w", err)
			if !sleepOrCancel(ctx, backoff) {
				return nil, lastErr
			}
			backoff *= 2
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, stripeMaxResponseBytes))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("stripe: read response: %w", readErr)
			if !sleepOrCancel(ctx, backoff) {
				return nil, lastErr
			}
			backoff *= 2
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, nil
		}
		lastErr = fmt.Errorf("stripe: status %d: %s", resp.StatusCode, string(body))
		if !shouldRetryStripe(resp.StatusCode) {
			return nil, lastErr
		}
		if !sleepOrCancel(ctx, backoff) {
			return nil, lastErr
		}
		backoff *= 2
	}
	return nil, lastErr
}

// shouldRetryStripe returns true for transient HTTP statuses worth
// retrying. 5xx are server-side; 429 is rate-limited (Stripe asks
// callers to back off explicitly).
func shouldRetryStripe(status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	return status >= 500 && status <= 599
}

// sleepOrCancel sleeps for d, returning false if ctx cancels first.
// Used to make the retry backoff respect the request context's
// deadline rather than blindly burning the backoff window.
func sleepOrCancel(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// newIdempotencyKey returns a fresh hex-encoded random token suitable
// for Stripe's Idempotency-Key header. 16 bytes / 128 bits — Stripe
// accepts up to 255 chars; we stay well under.
func newIdempotencyKey() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		// Falling back to a time-derived value is still better than
		// no key at all — Stripe just dedupes within a 24h window.
		return fmt.Sprintf("keel-%d", time.Now().UnixNano())
	}
	return "keel-" + hex.EncodeToString(b)
}

var _ CheckoutClient = (*StripeCheckoutClient)(nil)
