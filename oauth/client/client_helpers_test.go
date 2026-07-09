package client

import (
	"context"
	"net/url"
	"testing"
)

func TestCallbackQueryContext_RoundTrip(t *testing.T) {
	q := url.Values{"merchant_id": {"M123"}, "state": {"s"}}
	got := CallbackQueryFromContext(WithCallbackQuery(context.Background(), q))
	if got.Get("merchant_id") != "M123" {
		t.Fatalf("merchant_id = %q, want M123", got.Get("merchant_id"))
	}
	// Unset context returns nil; Values.Get on nil is safe and returns "".
	if CallbackQueryFromContext(context.Background()).Get("merchant_id") != "" {
		t.Fatal("expected empty string from an unset context")
	}
}
