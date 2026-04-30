package payment

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeSecrets struct {
	values map[string]string
}

func (f fakeSecrets) GetSecret(_ context.Context, path string) (string, error) {
	if v, ok := f.values[path]; ok {
		return v, nil
	}
	return "", fmt.Errorf("no secret %q", path)
}

func signStripe(secret, body string, ts int64) string {
	payload := fmt.Sprintf("%d.%s", ts, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func TestStripeVerifier_HappyPath(t *testing.T) {
	secret := "whsec_test"
	body := `{"id":"evt_1"}`
	ts := time.Now().Unix()
	sig := signStripe(secret, body, ts)

	v := &StripeSignatureVerifier{Secrets: fakeSecrets{map[string]string{"stripe_webhook_secret": secret}}}
	if err := v.Verify(context.Background(), sig, []byte(body)); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestStripeVerifier_MissingHeader(t *testing.T) {
	v := &StripeSignatureVerifier{Secrets: fakeSecrets{map[string]string{"stripe_webhook_secret": "x"}}}
	if err := v.Verify(context.Background(), "", []byte(`{}`)); err == nil {
		t.Fatal("expected missing-header error")
	}
}

func TestStripeVerifier_BadSignature(t *testing.T) {
	secret := "whsec_test"
	body := `{"id":"evt_2"}`
	ts := time.Now().Unix()
	sig := fmt.Sprintf("t=%d,v1=deadbeef", ts)

	v := &StripeSignatureVerifier{Secrets: fakeSecrets{map[string]string{"stripe_webhook_secret": secret}}}
	err := v.Verify(context.Background(), sig, []byte(body))
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected signature mismatch, got %v", err)
	}
}

func TestStripeVerifier_StaleTimestamp(t *testing.T) {
	secret := "whsec_test"
	body := `{"id":"evt_3"}`
	ts := time.Now().Add(-10 * time.Minute).Unix()
	sig := signStripe(secret, body, ts)

	v := &StripeSignatureVerifier{Secrets: fakeSecrets{map[string]string{"stripe_webhook_secret": secret}}}
	err := v.Verify(context.Background(), sig, []byte(body))
	if err == nil || !strings.Contains(err.Error(), "tolerance window") {
		t.Fatalf("expected timestamp-window error, got %v", err)
	}
}

// P1-13: future-shifted timestamps must also be rejected. Without
// the absolute-distance check an attacker could extend the replay
// window arbitrarily by stamping the future side.
func TestStripeVerifier_FutureTimestamp(t *testing.T) {
	secret := "whsec_test"
	body := `{"id":"evt_4"}`
	ts := time.Now().Add(10 * time.Minute).Unix()
	sig := signStripe(secret, body, ts)

	v := &StripeSignatureVerifier{Secrets: fakeSecrets{map[string]string{"stripe_webhook_secret": secret}}}
	err := v.Verify(context.Background(), sig, []byte(body))
	if err == nil || !strings.Contains(err.Error(), "tolerance window") {
		t.Fatalf("expected timestamp-window error for future ts, got %v", err)
	}
}

// P1-12: multi-secret rotation. Operators write `current\nprevious`
// during a rotation window; any signature signed with either key
// must verify.
func TestStripeVerifier_RotatesSecrets(t *testing.T) {
	current := "whsec_current"
	previous := "whsec_previous"
	body := `{"id":"evt_5"}`
	ts := time.Now().Unix()
	sig := signStripe(previous, body, ts)

	v := &StripeSignatureVerifier{Secrets: fakeSecrets{map[string]string{
		"stripe_webhook_secret": current + "\n" + previous,
	}}}
	if err := v.Verify(context.Background(), sig, []byte(body)); err != nil {
		t.Fatalf("rotation: previous key should still verify: %v", err)
	}
}

func TestStripeVerifier_MalformedHeader(t *testing.T) {
	v := &StripeSignatureVerifier{Secrets: fakeSecrets{map[string]string{"stripe_webhook_secret": "x"}}}
	err := v.Verify(context.Background(), "garbage", []byte(`{}`))
	if err == nil {
		t.Fatal("expected error for malformed header")
	}
}

func TestLemonSqueezyVerifier_HappyPath(t *testing.T) {
	secret := "ls_secret"
	body := `{"meta":{"event_name":"order_created"},"data":{"id":"1"}}`
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	sig := hex.EncodeToString(mac.Sum(nil))

	v := &LemonSqueezySignatureVerifier{Secrets: fakeSecrets{map[string]string{"lemonsqueezy_webhook_secret": secret}}}
	if err := v.Verify(context.Background(), sig, []byte(body)); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestLemonSqueezyVerifier_BadSignature(t *testing.T) {
	v := &LemonSqueezySignatureVerifier{Secrets: fakeSecrets{map[string]string{"lemonsqueezy_webhook_secret": "x"}}}
	err := v.Verify(context.Background(), "nope", []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected mismatch error, got %v", err)
	}
}

// FuzzStripeSignatureHeader exercises the Stripe-Signature header
// parser against arbitrary bytes. The verifier must never panic on
// a malformed header — the wire-facing entry point sees attacker-
// controlled input on every webhook delivery, and a panic there is
// a single-request DoS.
//
// The fuzzer cannot produce a forged HMAC, so every Verify call here
// is expected to return an error. The interesting failure modes are
// panics — index out of range on a header like "t=,v1=" or "v1",
// allocation explosions on pathological lengths, etc.
func FuzzStripeSignatureHeader(f *testing.F) {
	f.Add("t=1700000000,v1=abc", []byte(`{"id":"x"}`))
	f.Add("", []byte(""))
	f.Add("garbage", []byte("garbage"))
	f.Add("t=,v1=", []byte("{}"))
	f.Add("t=1700000000", []byte("{}"))
	f.Add("v1=abc", []byte("{}"))
	f.Add(",,,", []byte(""))
	f.Add("t=999999999999999999999999,v1=abc", []byte("{}"))

	v := &StripeSignatureVerifier{
		Secrets:   fakeSecrets{map[string]string{"stripe_webhook_secret": "sec"}},
		Tolerance: 5 * time.Minute,
		Now:       func() time.Time { return time.Unix(1700000000, 0) },
	}

	f.Fuzz(func(t *testing.T, header string, body []byte) {
		_ = v.Verify(context.Background(), header, body)
	})
}

// FuzzLemonSqueezyVerifier exercises the LemonSqueezy signature
// verifier against arbitrary bytes. Same panic-resistance contract
// as the Stripe fuzzer.
func FuzzLemonSqueezyVerifier(f *testing.F) {
	f.Add("abc123", []byte(`{}`))
	f.Add("", []byte(""))
	f.Add("not-hex", []byte("body"))
	f.Add(strings.Repeat("a", 1024), []byte("body"))

	v := &LemonSqueezySignatureVerifier{
		Secrets: fakeSecrets{map[string]string{"lemonsqueezy_webhook_secret": "sec"}},
	}

	f.Fuzz(func(t *testing.T, header string, body []byte) {
		_ = v.Verify(context.Background(), header, body)
	})
}
