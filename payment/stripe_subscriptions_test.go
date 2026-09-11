package payment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStripeSubscriptionChanges(t *testing.T) {
	var posted []map[string]string
	currentPlanPrice := "price_s"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/subscriptions/sub_1" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"items":{"data":[{"id":"si_addon","price":{"id":"price_a"}},{"id":"si_plan","price":{"id":"` + currentPlanPrice + `"}}]}}`))
			return
		}
		_ = r.ParseForm()
		form := map[string]string{}
		for k := range r.Form {
			form[k] = r.Form.Get(k)
		}
		if price := r.Form.Get("items[0][price]"); price != "" {
			currentPlanPrice = price
		}
		posted = append(posted, form)
		_, _ = w.Write([]byte(`{"id":"sub_1"}`))
	}))
	defer srv.Close()
	c := &StripeCheckoutClient{Secrets: intentSecrets{}, BaseURL: srv.URL}

	if err := c.ChangeSubscriptionPrice(context.Background(), "sub_1", "price_s", "price_p", "always_invoice"); err != nil {
		t.Fatal(err)
	}
	// A retry after the provider succeeded but before the local transaction
	// committed recognizes the target price and does not fail or post again.
	if err := c.ChangeSubscriptionPrice(context.Background(), "sub_1", "price_s", "price_p", "always_invoice"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := c.CancelSubscriptionAtPeriodEnd(context.Background(), "sub_1"); err != nil {
		t.Fatal(err)
	}
	if len(posted) != 2 ||
		posted[0]["items[0][id]"] != "si_plan" || posted[0]["items[0][price]"] != "price_p" || posted[0]["proration_behavior"] != "always_invoice" ||
		posted[1]["cancel_at_period_end"] != "true" {
		t.Fatalf("posted = %v", posted)
	}
	if err := c.ChangeSubscriptionPrice(context.Background(), "sub_1", "price_missing", "price_g", ""); err == nil {
		t.Fatal("multi-item subscription changed without a matching item")
	}
}
