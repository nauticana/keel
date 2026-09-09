package payment

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateRefund_FormAndStatusMapping(t *testing.T) {
	var got map[string]string
	var idem string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"currency":"usd"}`))
			return
		}
		_ = r.ParseForm()
		idem = r.Header.Get("Idempotency-Key")
		got = map[string]string{}
		for k := range r.Form {
			got[k] = r.Form.Get(k)
		}
		_, _ = w.Write([]byte(`{"id":"re_1","status":"pending","amount":500,"currency":"usd"}`))
	}))
	defer srv.Close()
	c := newTestChargeClient(srv)
	res, err := c.CreateRefund(context.Background(), RefundRequest{
		PaymentID: "pi_1", AmountMinor: 500, Currency: "USD", IdempotencyKey: "refund-42", Reason: "requested_by_customer",
		Metadata: map[string]string{"order": "42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["payment_intent"] != "pi_1" || got["amount"] != "500" || got["reason"] != "requested_by_customer" || got["metadata[order]"] != "42" || idem != "refund-42" {
		t.Fatalf("form=%v idem=%s", got, idem)
	}
	if res.RefundID != "re_1" || res.Status != RefundPending || res.AmountMinor != 500 || res.Currency != "USD" {
		t.Fatalf("res=%+v", res)
	}
}

func TestCreateRefund_ValidationAndProviderErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"currency":"usd"}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"charge_already_refunded","message":"…"}}`))
	}))
	defer srv.Close()
	c := newTestChargeClient(srv)
	for _, req := range []RefundRequest{
		{AmountMinor: 1, Currency: "USD", IdempotencyKey: "k"},
		{PaymentID: "pi", Currency: "USD", IdempotencyKey: "k"},
		{PaymentID: "pi", AmountMinor: 1, Currency: "USD"},
	} {
		if _, err := c.CreateRefund(context.Background(), req); err == nil {
			t.Fatalf("expected validation error for %+v", req)
		}
	}
	_, err := c.CreateRefund(context.Background(), RefundRequest{PaymentID: "pi", AmountMinor: 1, Currency: "USD", IdempotencyKey: "k"})
	if err == nil || err.Error() != "refund: stripe 400 charge_already_refunded" {
		t.Fatalf("err=%v", err)
	}
}

func TestCreateRefund_CurrencyMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"currency":"eur"}`))
			return
		}
		t.Fatal("refund POST must not run after currency mismatch")
	}))
	defer srv.Close()
	if _, err := newTestChargeClient(srv).CreateRefund(context.Background(), RefundRequest{PaymentID: "pi", AmountMinor: 500, Currency: "USD", IdempotencyKey: "k"}); err == nil {
		t.Fatal("currency mismatch must fail")
	}
}

func TestCreateRefund_AmountMismatchReturnsResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"currency":"usd"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"re_9","status":"succeeded","amount":400,"currency":"usd"}`))
	}))
	defer srv.Close()
	res, err := newTestChargeClient(srv).CreateRefund(context.Background(), RefundRequest{PaymentID: "pi", AmountMinor: 500, Currency: "USD", IdempotencyKey: "k"})
	if !errors.Is(err, ErrRefundAmountMismatch) || res.RefundID != "re_9" || res.AmountMinor != 400 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
