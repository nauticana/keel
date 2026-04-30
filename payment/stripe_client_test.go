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
