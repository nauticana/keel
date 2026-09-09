package payment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type intentSecrets struct{}

func (intentSecrets) GetSecret(context.Context, string) (string, error) { return "sk_test", nil }

func TestCreateSetupIntent_CreatesCustomerAndEphemeralKey(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/customers":
			if r.Form.Get("email") != "a@b" || r.Form.Get("metadata[user_id]") != "7" {
				t.Errorf("customer form=%v", r.Form)
			}
			_, _ = w.Write([]byte(`{"id":"cus_1"}`))
		case "/ephemeral_keys":
			if r.Header.Get("Stripe-Version") == "" {
				t.Error("Stripe-Version header missing from ephemeral-key request")
			}
			if r.Form.Get("customer") != "cus_1" {
				t.Errorf("ephemeral form=%v", r.Form)
			}
			_, _ = w.Write([]byte(`{"secret":"ek_1"}`))
		case "/setup_intents":
			if r.Header.Get("Stripe-Version") != "" {
				t.Error("Stripe-Version unexpectedly changed the setup-intent API version")
			}
			if r.Form.Get("customer") != "cus_1" || r.Form.Get("usage") != "off_session" || r.Form.Get("metadata[user_id]") != "7" {
				t.Errorf("setup form=%v", r.Form)
			}
			_, _ = w.Write([]byte(`{"id":"seti_1","client_secret":"seti_1_secret"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := &StripeCheckoutClient{Secrets: intentSecrets{}, BaseURL: srv.URL}
	res, err := c.CreateSetupIntent(context.Background(), IntentRequest{Email: "a@b", Metadata: map[string]string{"user_id": "7"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IntentID != "seti_1" || res.ClientSecret != "seti_1_secret" || res.CustomerID != "cus_1" || res.EphemeralKey != "ek_1" || len(paths) != 3 {
		t.Fatalf("res=%+v paths=%v", res, paths)
	}
}

func TestCreatePaymentIntent_ReusesCustomerAndValidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/ephemeral_keys":
			_, _ = w.Write([]byte(`{"secret":"ek_2"}`))
		case "/payment_intents":
			if r.Form.Get("amount") != "1250" || r.Form.Get("currency") != "usd" || r.Form.Get("customer") != "cus_9" {
				t.Errorf("payment form=%v", r.Form)
			}
			_, _ = w.Write([]byte(`{"id":"pi_1","client_secret":"pi_1_secret"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	c := &StripeCheckoutClient{Secrets: intentSecrets{}, BaseURL: srv.URL}
	if _, err := c.CreatePaymentIntent(context.Background(), IntentRequest{CustomerID: "cus_9"}); err == nil {
		t.Fatal("amount and currency must be required")
	}
	res, err := c.CreatePaymentIntent(context.Background(), IntentRequest{CustomerID: "cus_9", Amount: 1250, Currency: "usd"})
	if err != nil || res.ClientSecret != "pi_1_secret" || res.CustomerID != "cus_9" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
