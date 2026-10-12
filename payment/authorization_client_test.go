package payment

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type route struct {
	status int
	body   string
}

// stripeRoutes serves canned responses keyed by "METHOD path" and records each request form.
func stripeRoutes(t *testing.T, routes map[string]route) (*StripeChargeClient, map[string]url.Values) {
	t.Helper()
	seen := map[string]url.Values{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		route, ok := routes[key]
		if !ok {
			t.Errorf("unexpected request %s", key)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(b))
		form.Set("Idempotency-Key", r.Header.Get("Idempotency-Key"))
		seen[key] = form
		w.WriteHeader(route.status)
		io.WriteString(w, route.body)
	}))
	t.Cleanup(srv.Close)
	return newTestChargeClient(srv), seen
}

func TestAuthorize_PlacesManualCaptureHold(t *testing.T) {
	c, seen := stripeRoutes(t, map[string]route{"POST /payment_intents": {200, `{"id":"pi_1","status":"requires_capture","amount_capturable":1150,
		"latest_charge":{"payment_method_details":{"card":{"capture_before":1700000000}}}}`}})
	res, err := c.Authorize(context.Background(), ChargeRequest{CustomerToken: "cus_1", PaymentMethodToken: "pm_1", AmountMinor: 1150, Currency: "USD", IdempotencyKey: "ride-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != ChargeAuthorized || res.ProviderChargeID != "pi_1" || res.AmountAuthorizedMinor != 1150 || !res.ExpiresAt.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("result = %+v", res)
	}
	form := seen["POST /payment_intents"]
	if form.Get("capture_method") != "manual" || form.Get("off_session") != "true" || form.Get("Idempotency-Key") != "ride-1" {
		t.Fatalf("form = %v", form)
	}
}

func TestAuthorize_DeclineCarriesReason(t *testing.T) {
	c, _ := stripeRoutes(t, map[string]route{"POST /payment_intents": {402, `{"error":{"code":"card_declined","decline_code":"insufficient_funds","message":"Your card has insufficient funds.",
		"payment_intent":{"id":"pi_1","status":"requires_payment_method"}}}`}})
	res, err := c.Authorize(context.Background(), ChargeRequest{AmountMinor: 100, Currency: "USD"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != ChargeFailed || res.DeclineReason != DeclineInsufficientFunds || res.ProviderDeclineCode != "insufficient_funds" || res.ProviderChargeID != "pi_1" {
		t.Fatalf("result = %+v", res)
	}
}

func TestAuthorize_SucceededIsNotAuthorized(t *testing.T) {
	c, _ := stripeRoutes(t, map[string]route{"POST /payment_intents": {200, `{"id":"pi_1","status":"succeeded"}`}})
	res, err := c.Authorize(context.Background(), ChargeRequest{AmountMinor: 100, Currency: "USD"})
	if err != nil || res.Status != ChargeFailed {
		t.Fatalf("result = %+v, %v", res, err)
	}
}

func TestAuthorize_MalformedLatestChargeFails(t *testing.T) {
	c, _ := stripeRoutes(t, map[string]route{"POST /payment_intents": {200, `{"id":"pi_1","status":"requires_capture","latest_charge":{"payment_method_details":"x"}}`}})
	if _, err := c.Authorize(context.Background(), ChargeRequest{AmountMinor: 100, Currency: "USD"}); err == nil {
		t.Fatal("malformed latest_charge must fail")
	}
}

func TestCapture(t *testing.T) {
	c, seen := stripeRoutes(t, map[string]route{"POST /payment_intents/pi_1/capture": {200, `{"id":"pi_1","status":"succeeded"}`}})
	if err := c.Capture(context.Background(), "pi_1", 900, "cap-1"); err != nil {
		t.Fatal(err)
	}
	if form := seen["POST /payment_intents/pi_1/capture"]; form.Get("amount_to_capture") != "900" || form.Get("Idempotency-Key") != "cap-1" {
		t.Fatalf("form = %v", form)
	}
	if err := c.Capture(context.Background(), "pi_1", 900, ""); err == nil {
		t.Fatal("capture without an idempotency key must fail")
	}
}

func TestCapture_ProviderErrorFails(t *testing.T) {
	c, _ := stripeRoutes(t, map[string]route{"POST /payment_intents/pi_1/capture": {400, `{"error":{"code":"payment_intent_unexpected_state","message":"canceled"}}`}})
	if err := c.Capture(context.Background(), "pi_1", 900, "cap-1"); err == nil {
		t.Fatal("capture of a canceled hold must fail")
	}
}

func TestIncrementAuthorization(t *testing.T) {
	held := `{"id":"pi_1","status":"requires_capture","amount_capturable":1000,
		"latest_charge":{"payment_method_details":{"card":{"incremental_authorization":{"status":"available"}}}}}`
	c, seen := stripeRoutes(t, map[string]route{
		"GET /payment_intents/pi_1":                          {200, held},
		"POST /payment_intents/pi_1/increment_authorization": {200, `{"id":"pi_1","status":"requires_capture","amount_capturable":1400}`},
	})
	res, err := c.IncrementAuthorization(context.Background(), "pi_1", 1400, "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != ChargeAuthorized || res.AmountAuthorizedMinor != 1400 {
		t.Fatalf("result = %+v", res)
	}
	if form := seen["POST /payment_intents/pi_1/increment_authorization"]; form.Get("amount") != "1400" || form.Get("Idempotency-Key") != "inc-1" {
		t.Fatalf("form = %v", form)
	}
}

func TestIncrementAuthorization_NotSupported(t *testing.T) {
	c, _ := stripeRoutes(t, map[string]route{"GET /payment_intents/pi_1": {200, `{"id":"pi_1","status":"requires_capture","latest_charge":"ch_1"}`}})
	if _, err := c.IncrementAuthorization(context.Background(), "pi_1", 1400, "inc-1"); !errors.Is(err, ErrIncrementNotSupported) {
		t.Fatalf("err = %v", err)
	}
}

func TestIncrementAuthorization_DeclineKeepsHold(t *testing.T) {
	c, _ := stripeRoutes(t, map[string]route{
		"GET /payment_intents/pi_1": {200, `{"id":"pi_1","status":"requires_capture","amount_capturable":1000,
			"latest_charge":{"payment_method_details":{"card":{"incremental_authorization":{"status":"available"}}}}}`},
		"POST /payment_intents/pi_1/increment_authorization": {402, `{"error":{"code":"card_declined","decline_code":"do_not_honor","message":"declined"}}`},
	})
	res, err := c.IncrementAuthorization(context.Background(), "pi_1", 1400, "inc-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != ChargeFailed || res.DeclineReason != DeclineCardDeclined || res.AmountAuthorizedMinor != 1000 {
		t.Fatalf("result = %+v", res)
	}
}

func TestCancelAuthorization(t *testing.T) {
	c, seen := stripeRoutes(t, map[string]route{"POST /payment_intents/pi_1/cancel": {200, `{"id":"pi_1","status":"canceled"}`}})
	if err := c.CancelAuthorization(context.Background(), "pi_1", "abandoned"); err != nil {
		t.Fatal(err)
	}
	if seen["POST /payment_intents/pi_1/cancel"].Get("cancellation_reason") != "abandoned" {
		t.Fatalf("form = %v", seen)
	}
	if err := c.CancelAuthorization(context.Background(), "pi_1", "bored"); err == nil {
		t.Fatal("unsupported reason must fail")
	}
}

func TestCancelAuthorization_AlreadyCanceledIsSuccess(t *testing.T) {
	c, _ := stripeRoutes(t, map[string]route{"POST /payment_intents/pi_1/cancel": {400, `{"error":{"code":"payment_intent_unexpected_state","payment_intent":{"id":"pi_1","status":"canceled"}}}`}})
	if err := c.CancelAuthorization(context.Background(), "pi_1", ""); err != nil {
		t.Fatal(err)
	}
}

func TestCancelAuthorization_CapturedFails(t *testing.T) {
	c, _ := stripeRoutes(t, map[string]route{"POST /payment_intents/pi_1/cancel": {400, `{"error":{"code":"payment_intent_unexpected_state","payment_intent":{"id":"pi_1","status":"succeeded"}}}`}})
	if err := c.CancelAuthorization(context.Background(), "pi_1", ""); err == nil {
		t.Fatal("canceling a captured payment must fail")
	}
}

func TestStripeDeclineReason(t *testing.T) {
	for code, want := range map[string]DeclineReason{
		"":                                      "",
		"insufficient_funds":                    DeclineInsufficientFunds,
		"expired_card":                          DeclineExpiredCard,
		"incorrect_cvc":                         DeclineIncorrectCVC,
		"processing_error":                      DeclineProcessingError,
		"payment_intent_authentication_failure": DeclineAuthenticationFailed,
		"generic_decline":                       DeclineCardDeclined,
		"velocity_exceeded":                     DeclineOther,
	} {
		if got := stripeDeclineReason(code); got != want {
			t.Errorf("%q = %q, want %q", code, got, want)
		}
	}
}
