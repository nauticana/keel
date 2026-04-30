package payment

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateCheckoutSession_FormBody(t *testing.T) {
	var captured struct {
		body       string
		authHeader string
		ctype      string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		captured.body = string(b)
		captured.authHeader = r.Header.Get("Authorization")
		captured.ctype = r.Header.Get("Content-Type")
		json.NewEncoder(w).Encode(map[string]string{"url": "https://checkout.stripe.com/pay/xyz"})
	}))
	defer srv.Close()

	c := &StripeCheckoutClient{
		Secrets:    fakeSecrets{map[string]string{"stripe_secret_key": "sk_test"}},
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	}
	url, err := c.CreateCheckoutSession(context.Background(), CheckoutRequest{
		Mode:       "subscription",
		PriceID:    "price_123",
		Quantity:   1,
		Email:      "foo@bar.com",
		SuccessURL: "https://app/ok",
		CancelURL:  "https://app/cancel",
		Metadata:   map[string]string{"partner_id": "42"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "https://checkout.stripe.com/pay/xyz" {
		t.Fatalf("unexpected url: %s", url)
	}
	for _, want := range []string{
		"mode=subscription",
		"customer_email=foo%40bar.com",
		"line_items%5B0%5D%5Bprice%5D=price_123",
		"line_items%5B0%5D%5Bquantity%5D=1",
		"metadata%5Bpartner_id%5D=42",
		"success_url=https%3A%2F%2Fapp%2Fok",
		"cancel_url=https%3A%2F%2Fapp%2Fcancel",
	} {
		if !strings.Contains(captured.body, want) {
			t.Errorf("body missing %q\ngot: %s", want, captured.body)
		}
	}
	if !strings.HasPrefix(captured.authHeader, "Basic ") {
		t.Errorf("expected Basic auth, got %q", captured.authHeader)
	}
	if captured.ctype != "application/x-www-form-urlencoded" {
		t.Errorf("unexpected Content-Type %q", captured.ctype)
	}
}

func TestCreateCheckoutSession_SetupMode(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		json.NewEncoder(w).Encode(map[string]string{"url": "https://checkout.stripe.com/c/pay/setup_xyz"})
	}))
	defer srv.Close()

	c := &StripeCheckoutClient{
		Secrets:    fakeSecrets{map[string]string{"stripe_secret_key": "sk_test"}},
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	}
	url, err := c.CreateCheckoutSession(context.Background(), CheckoutRequest{
		Mode:       "setup",
		SuccessURL: "https://app/ok",
		CancelURL:  "https://app/cancel",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "https://checkout.stripe.com/c/pay/setup_xyz" {
		t.Fatalf("unexpected url: %s", url)
	}
	if !strings.Contains(capturedBody, "mode=setup") {
		t.Errorf("body missing mode=setup\ngot: %s", capturedBody)
	}
	if strings.Contains(capturedBody, "line_items") {
		t.Errorf("setup mode must not send line_items\ngot: %s", capturedBody)
	}
}

func TestCreateCheckoutSession_NonOKResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"No such price"}}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	c := &StripeCheckoutClient{
		Secrets:    fakeSecrets{map[string]string{"stripe_secret_key": "sk_test"}},
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	}
	_, err := c.CreateCheckoutSession(context.Background(), CheckoutRequest{PriceID: "price_x"})
	if err == nil {
		t.Fatal("expected error on 400 response")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected status in error, got %v", err)
	}
}

// v0.5.1-B: setup-mode metadata mirrored into setup_intent_data so
// `setup_intent.succeeded` arrives self-contained.
func TestCreateCheckoutSession_SetupMode_MirrorsMetadata(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		json.NewEncoder(w).Encode(map[string]string{"url": "https://checkout.stripe.com/c/pay/setup_xyz"})
	}))
	defer srv.Close()

	c := &StripeCheckoutClient{
		Secrets:    fakeSecrets{map[string]string{"stripe_secret_key": "sk_test"}},
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	}
	_, err := c.CreateCheckoutSession(context.Background(), CheckoutRequest{
		Mode:       "setup",
		SuccessURL: "https://app/ok",
		CancelURL:  "https://app/cancel",
		Metadata:   map[string]string{"user_id": "42", "partner_id": "7"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{
		"metadata%5Buser_id%5D=42",
		"metadata%5Bpartner_id%5D=7",
		"setup_intent_data%5Bmetadata%5D%5Buser_id%5D=42",
		"setup_intent_data%5Bmetadata%5D%5Bpartner_id%5D=7",
	} {
		if !strings.Contains(capturedBody, want) {
			t.Errorf("setup-mode body missing %q\ngot: %s", want, capturedBody)
		}
	}
}

// v0.5.1-B: setup_intent_data mirroring is gated on mode=setup; payment
// and subscription modes get top-level metadata only.
func TestCreateCheckoutSession_NonSetupMode_NoMirror(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		json.NewEncoder(w).Encode(map[string]string{"url": "https://checkout.stripe.com/pay/xyz"})
	}))
	defer srv.Close()

	c := &StripeCheckoutClient{
		Secrets:    fakeSecrets{map[string]string{"stripe_secret_key": "sk_test"}},
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	}
	_, err := c.CreateCheckoutSession(context.Background(), CheckoutRequest{
		Mode:     "subscription",
		PriceID:  "price_x",
		Metadata: map[string]string{"user_id": "42"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(capturedBody, "setup_intent_data") {
		t.Errorf("subscription-mode body must not include setup_intent_data\ngot: %s", capturedBody)
	}
}

// v0.5.1-C: public Get round-trips with bounded read + Basic auth, and
// MUST NOT send Idempotency-Key (Stripe rejects it on read endpoints).
func TestStripeClient_Get_RoundTrip(t *testing.T) {
	var captured struct {
		method         string
		path           string
		idempotency    string
		authHeader     string
		query          string
		contentType    string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.idempotency = r.Header.Get("Idempotency-Key")
		captured.authHeader = r.Header.Get("Authorization")
		captured.query = r.URL.RawQuery
		captured.contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"seti_xyz","payment_method":"pm_abc"}`))
	}))
	defer srv.Close()

	c := &StripeCheckoutClient{
		Secrets:    fakeSecrets{map[string]string{"stripe_secret_key": "sk_test"}},
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	}
	body, err := c.Get(context.Background(), "/setup_intents/seti_xyz", map[string][]string{
		"expand[]": {"payment_method"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(body), `"id":"seti_xyz"`) {
		t.Fatalf("response body lost: %s", string(body))
	}
	if captured.method != http.MethodGet {
		t.Errorf("expected GET, got %s", captured.method)
	}
	if captured.path != "/setup_intents/seti_xyz" {
		t.Errorf("unexpected path %q", captured.path)
	}
	if captured.idempotency != "" {
		t.Errorf("Idempotency-Key must not be set on GET; got %q", captured.idempotency)
	}
	if !strings.HasPrefix(captured.authHeader, "Basic ") {
		t.Errorf("expected Basic auth, got %q", captured.authHeader)
	}
	if captured.contentType != "" {
		t.Errorf("GET should not set Content-Type; got %q", captured.contentType)
	}
	if !strings.Contains(captured.query, "expand%5B%5D=payment_method") {
		t.Errorf("query params lost: %q", captured.query)
	}
}

func TestCreatePortalSession(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		json.NewEncoder(w).Encode(map[string]string{"url": "https://billing.stripe.com/p/session/abc"})
	}))
	defer srv.Close()

	c := &StripeCheckoutClient{
		Secrets:    fakeSecrets{map[string]string{"stripe_secret_key": "sk_test"}},
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	}
	url, err := c.CreatePortalSession(context.Background(), "cus_123", "https://app/back")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url == "" {
		t.Fatal("expected portal url")
	}
	if !strings.Contains(capturedBody, "customer=cus_123") {
		t.Errorf("missing customer param: %s", capturedBody)
	}
}
