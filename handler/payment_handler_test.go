package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/payment"
)

// fakeCheckout records the last CheckoutRequest it saw and returns a
// canned URL. Lets us assert on what the handler hands the port without
// touching Stripe.
type fakeCheckout struct {
	last    payment.CheckoutRequest
	called  bool
	respURL string
	err     error
}

func (f *fakeCheckout) CreateCheckoutSession(_ context.Context, req payment.CheckoutRequest) (string, error) {
	f.called = true
	f.last = req
	if f.err != nil {
		return "", f.err
	}
	return f.respURL, nil
}

func (f *fakeCheckout) CreatePortalSession(context.Context, string, string) (string, error) {
	return "", nil
}

func newCheckoutHandler(checkout payment.CheckoutClient) *AbstractPaymentHandler {
	return &AbstractPaymentHandler{
		Checkout:             checkout,
		AllowedRedirectHosts: []string{"app.example"},
		AllowedPriceIDs:      []string{"price_ok"},
		AllowGuestCheckout:   true, // gate-off auth; B5 covers the price/mode gate
	}
}

func postCheckout(h *AbstractPaymentHandler, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/billing/checkout", strings.NewReader(string(raw)))
	rec := httptest.NewRecorder()
	h.CreateCheckout(rec, req)
	return rec
}

// B5: setup mode with empty priceId is now legal — the gate must skip
// the priceAllowed check and the request reaches the CheckoutClient.
func TestCreateCheckout_SetupMode_EmptyPriceID_Succeeds(t *testing.T) {
	fake := &fakeCheckout{respURL: "https://checkout.stripe.com/c/pay/setup_xyz"}
	h := newCheckoutHandler(fake)

	rec := postCheckout(h, map[string]any{
		"mode":       "setup",
		"successUrl": "https://app.example/ok",
		"cancelUrl":  "https://app.example/cancel",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !fake.called {
		t.Fatal("CreateCheckoutSession was not invoked")
	}
	if fake.last.Mode != "setup" {
		t.Errorf("mode forwarded: got %q, want setup", fake.last.Mode)
	}
	if fake.last.PriceID != "" {
		t.Errorf("priceID forwarded: got %q, want empty", fake.last.PriceID)
	}
}

// B5: a setup-mode caller that passes a priceId is rejected up-front,
// since Stripe ignores line_items in setup mode and would otherwise
// surface as a 502 from the downstream 400.
func TestCreateCheckout_SetupMode_NonEmptyPriceID_Rejected(t *testing.T) {
	fake := &fakeCheckout{respURL: "unused"}
	h := newCheckoutHandler(fake)

	rec := postCheckout(h, map[string]any{
		"mode":       "setup",
		"priceId":    "price_ok",
		"successUrl": "https://app.example/ok",
		"cancelUrl":  "https://app.example/cancel",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if fake.called {
		t.Fatal("CreateCheckoutSession should not have been called")
	}
}

// Pre-existing v0.4.x behavior: subscription mode still requires a
// priceId in the allowlist. Empty / unlisted ids are rejected.
func TestCreateCheckout_SubscriptionMode_RequiresAllowedPriceID(t *testing.T) {
	fake := &fakeCheckout{respURL: "unused"}
	h := newCheckoutHandler(fake)

	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"empty priceId", map[string]any{
			"mode":       "subscription",
			"successUrl": "https://app.example/ok",
			"cancelUrl":  "https://app.example/cancel",
		}},
		{"unlisted priceId", map[string]any{
			"mode":       "subscription",
			"priceId":    "price_attacker",
			"successUrl": "https://app.example/ok",
			"cancelUrl":  "https://app.example/cancel",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake.called = false
			rec := postCheckout(h, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status: got %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if fake.called {
				t.Fatal("CreateCheckoutSession should not have been called")
			}
		})
	}
}

// Subscription mode with an allowed price routes through to the port.
func TestCreateCheckout_SubscriptionMode_HappyPath(t *testing.T) {
	fake := &fakeCheckout{respURL: "https://checkout.stripe.com/c/pay/sub_xyz"}
	h := newCheckoutHandler(fake)

	rec := postCheckout(h, map[string]any{
		"mode":       "subscription",
		"priceId":    "price_ok",
		"successUrl": "https://app.example/ok",
		"cancelUrl":  "https://app.example/cancel",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if fake.last.PriceID != "price_ok" {
		t.Errorf("priceID forwarded: got %q, want price_ok", fake.last.PriceID)
	}
}

// Empty mode preserves v0.4.x behavior — defaults to "subscription"
// and the same priceId gate applies.
func TestCreateCheckout_EmptyMode_DefaultsToSubscription(t *testing.T) {
	fake := &fakeCheckout{respURL: "https://checkout.stripe.com/c/pay/sub_xyz"}
	h := newCheckoutHandler(fake)

	rec := postCheckout(h, map[string]any{
		"priceId":    "price_ok",
		"successUrl": "https://app.example/ok",
		"cancelUrl":  "https://app.example/cancel",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if fake.last.Mode != "subscription" {
		t.Errorf("mode forwarded: got %q, want subscription", fake.last.Mode)
	}
}

// B7: hostname-only entries match the parsed URL's hostname,
// port-insensitively. Pre-v0.4.7 this rejected legitimate non-default
// ports because matching was against the raw host:port pair.
func TestCreateCheckout_AllowedRedirectHosts_HostnameMatchesNonDefaultPort(t *testing.T) {
	fake := &fakeCheckout{respURL: "https://checkout.stripe.com/c/pay/sub_xyz"}
	h := newCheckoutHandler(fake) // AllowedRedirectHosts = ["app.example"]

	rec := postCheckout(h, map[string]any{
		"mode":       "subscription",
		"priceId":    "price_ok",
		"successUrl": "https://app.example:8443/ok",
		"cancelUrl":  "https://app.example:8443/cancel",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("hostname-only allowlist must accept :8443: got %d, body=%s", rec.Code, rec.Body.String())
	}
}

// B7: entries containing a colon stay port-strict — operators can opt
// into "this exact host:port and nothing else" gating.
func TestCreateCheckout_AllowedRedirectHosts_PortStrictEntry(t *testing.T) {
	fake := &fakeCheckout{respURL: "https://checkout.stripe.com/c/pay/sub_xyz"}
	h := newCheckoutHandler(fake)
	h.AllowedRedirectHosts = []string{"app.example:8443"}

	t.Run("matches exact host:port", func(t *testing.T) {
		fake.called = false
		rec := postCheckout(h, map[string]any{
			"mode":       "subscription",
			"priceId":    "price_ok",
			"successUrl": "https://app.example:8443/ok",
			"cancelUrl":  "https://app.example:8443/cancel",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rejects different port", func(t *testing.T) {
		fake.called = false
		rec := postCheckout(h, map[string]any{
			"mode":       "subscription",
			"priceId":    "price_ok",
			"successUrl": "https://app.example:9000/ok",
			"cancelUrl":  "https://app.example:9000/cancel",
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("got %d, body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rejects no port", func(t *testing.T) {
		fake.called = false
		rec := postCheckout(h, map[string]any{
			"mode":       "subscription",
			"priceId":    "price_ok",
			"successUrl": "https://app.example/ok",
			"cancelUrl":  "https://app.example/cancel",
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("got %d, body=%s", rec.Code, rec.Body.String())
		}
	})
}

// Unknown modes are rejected — guards against typos like "subscriptn"
// silently being forwarded to Stripe.
func TestCreateCheckout_UnknownMode_Rejected(t *testing.T) {
	fake := &fakeCheckout{respURL: "unused"}
	h := newCheckoutHandler(fake)

	rec := postCheckout(h, map[string]any{
		"mode":       "donate",
		"priceId":    "price_ok",
		"successUrl": "https://app.example/ok",
		"cancelUrl":  "https://app.example/cancel",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if fake.called {
		t.Fatal("CreateCheckoutSession should not have been called")
	}
}
