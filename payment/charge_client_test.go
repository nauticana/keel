package payment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func newTestChargeClient(srv *httptest.Server) *StripeChargeClient {
	return &StripeChargeClient{Stripe: &StripeCheckoutClient{
		Secrets:    fakeSecrets{map[string]string{"stripe_secret_key": "sk_test"}},
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
	}}
}

func TestCharge_ForwardsMetadata(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		json.NewEncoder(w).Encode(map[string]string{"id": "pi_1", "status": "succeeded"})
	}))
	defer srv.Close()

	res, err := newTestChargeClient(srv).Charge(context.Background(), ChargeRequest{
		CustomerToken:      "cus_1",
		PaymentMethodToken: "pm_1",
		AmountMinor:        1234,
		Currency:           "USD",
		IdempotencyKey:     "inv_99",
		Metadata:           map[string]string{"ride_id": "r1", "tip_amount": "200"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != ChargeSucceeded {
		t.Fatalf("status = %q, want succeeded", res.Status)
	}
	for _, want := range []string{
		"metadata%5Bride_id%5D=r1",
		"metadata%5Btip_amount%5D=200",
		"metadata%5Bidempotency_key%5D=inv_99",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\ngot: %s", want, body)
		}
	}
}

func TestCharge_RejectsInvalidMetadata(t *testing.T) {
	// Server must never be hit when metadata is invalid.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be called for invalid metadata")
	}))
	defer srv.Close()
	c := newTestChargeClient(srv)

	tooMany := make(map[string]string, maxMetadataPairs+1)
	for i := 0; i <= maxMetadataPairs; i++ {
		tooMany["k"+strconv.Itoa(i)] = "v"
	}

	cases := map[string]map[string]string{
		"reserved key": {reservedMetadataKey: "x"},
		"empty key":    {"": "x"},
		"long key":     {strings.Repeat("k", maxMetadataKeyLen+1): "x"},
		"long value":   {"ok": strings.Repeat("v", maxMetadataValLen+1)},
		"too many":     tooMany,
	}
	for name, md := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.Charge(context.Background(), ChargeRequest{
				CustomerToken:  "cus_1",
				AmountMinor:    100,
				Currency:       "USD",
				IdempotencyKey: "inv_1",
				Metadata:       md,
			})
			if !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("err = %v, want ErrInvalidMetadata", err)
			}
		})
	}
}
