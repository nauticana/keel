package payment

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/secret"
)

// StripeTolerance is the maximum age of a Stripe-Signature timestamp.
// Stripe's recommended default; requests older than this are rejected.
const StripeTolerance = 5 * time.Minute

// MaxSigHeaderBytes caps the inbound signature header at a length that
// is multiples larger than any legitimate provider header (Stripe and
// LemonSqueezy are well under 256 bytes) but small enough to bound
// the work an attacker can force on the verify path. A pathological
// header in the megabytes would otherwise feed strings.Split / hmac
// allocators on every parse attempt.
const MaxSigHeaderBytes = 1024

// clock is an injectable time source so tests can drive signature
// verification against a fixed instant.
type clock func() time.Time

// StripeSignatureVerifier verifies Stripe webhook signatures using
// HMAC-SHA256 over "<timestamp>.<body>" as specified by Stripe.
//
// Header format: "t=<unix_ts>,v1=<sig>[,v1=<sig>...]".
type StripeSignatureVerifier struct {
	Secrets    secret.SecretProvider
	SecretName string // default: "stripe_webhook_secret"
	Tolerance  time.Duration
	Now        clock // optional; defaults to time.Now
}

// NewStripeSignatureVerifier constructs a verifier with default settings.
func NewStripeSignatureVerifier(secrets secret.SecretProvider) *StripeSignatureVerifier {
	return &StripeSignatureVerifier{Secrets: secrets}
}

// Verify satisfies port.SignatureVerifier.
//
// Multi-secret rotation (P1-12): the secret value may carry multiple
// candidate keys separated by newlines. Verify tries each in
// constant-time order; any match passes. Operators rotate by writing
// `current\nprevious` into the secret store, deploying, then later
// dropping the previous value. No code change required to swap.
//
// Bidirectional staleness (P1-13): the timestamp window is checked
// with absolute distance — both "too old" and "too far in the future"
// fail. The previous one-sided check let an attacker with a future-
// shifted timestamp extend the replay window indefinitely.
func (v *StripeSignatureVerifier) Verify(ctx context.Context, sigHeader string, body []byte) error {
	secretName := v.SecretName
	if secretName == "" {
		secretName = "stripe_webhook_secret"
	}
	rawSecret, err := v.Secrets.GetSecret(ctx, secretName)
	if err != nil {
		return fmt.Errorf("failed to get stripe webhook secret: %w", err)
	}

	if sigHeader == "" {
		return fmt.Errorf("missing Stripe-Signature header")
	}
	if len(sigHeader) > MaxSigHeaderBytes {
		return fmt.Errorf("Stripe-Signature header too long")
	}

	var timestamp string
	var signatures []string
	for _, part := range strings.Split(sigHeader, ",") {
		// Tolerate stray whitespace introduced by proxies / curl-by-
		// hand replays (Stripe's spec is comma-only, but real wire
		// traffic occasionally includes spaces).
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			signatures = append(signatures, kv[1])
		}
	}

	if timestamp == "" || len(signatures) == 0 {
		return fmt.Errorf("invalid Stripe-Signature format")
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp in signature: %w", err)
	}

	tolerance := v.Tolerance
	if tolerance == 0 {
		tolerance = StripeTolerance
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	delta := now().Sub(time.Unix(ts, 0))
	if delta < 0 {
		delta = -delta
	}
	if delta > tolerance {
		return fmt.Errorf("webhook timestamp outside tolerance window")
	}

	signedPayload := timestamp + "." + string(body)
	for _, secret := range splitRotationSecrets(rawSecret) {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signedPayload))
		expectedSig := hex.EncodeToString(mac.Sum(nil))
		for _, sig := range signatures {
			if hmac.Equal([]byte(sig), []byte(expectedSig)) {
				return nil
			}
		}
	}
	return fmt.Errorf("stripe signature mismatch")
}

// splitRotationSecrets accepts a secret value that may carry one or
// more candidate keys separated by newlines or commas, trims each,
// and returns the non-empty entries. A single-secret deployment is
// the common case and produces a single-element slice.
func splitRotationSecrets(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// Split on either separator so operators can use whichever is
	// easier to enter in their secret-manager UI.
	rep := strings.NewReplacer(",", "\n").Replace(raw)
	parts := strings.Split(rep, "\n")
	out := parts[:0]
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// compile-time interface checks
var (
	_ SignatureVerifier = (*StripeSignatureVerifier)(nil)
	_ SignatureVerifier = (*LemonSqueezySignatureVerifier)(nil)
)
