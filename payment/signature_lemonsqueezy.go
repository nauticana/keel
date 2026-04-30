package payment

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/nauticana/keel/secret"
)

// LemonSqueezySignatureVerifier verifies LemonSqueezy webhooks. The
// provider signs the raw body directly with HMAC-SHA256 — there is NO
// timestamp in the signed-payload, so this verifier alone provides no
// replay-window guarantee.
//
// Replay protection therefore relies on the upstream idempotency layer:
//   - parser.go REJECTS payloads whose data.id is missing (refusing to
//     fabricate a synthetic event id),
//   - webhook.go's Process() looks up (provider, event_id) before any
//     handler dispatch and treats any prior row — regardless of status —
//     as a duplicate,
//   - the unique index on payment_webhook_log.(provider, event_id) is
//     the authoritative race guard.
//
// In other words: LemonSqueezy events are deduped by their data.id, not
// by a signature timestamp. Make sure every webhook source you point
// at this verifier emits stable, unique data.id values.
type LemonSqueezySignatureVerifier struct {
	Secrets    secret.SecretProvider
	SecretName string // default: "lemonsqueezy_webhook_secret"
}

func NewLemonSqueezySignatureVerifier(secrets secret.SecretProvider) *LemonSqueezySignatureVerifier {
	return &LemonSqueezySignatureVerifier{Secrets: secrets}
}

// Verify satisfies port.SignatureVerifier. Same multi-secret rotation
// rules as the Stripe verifier — see splitRotationSecrets.
func (v *LemonSqueezySignatureVerifier) Verify(ctx context.Context, sigHeader string, body []byte) error {
	secretName := v.SecretName
	if secretName == "" {
		secretName = "lemonsqueezy_webhook_secret"
	}
	rawSecret, err := v.Secrets.GetSecret(ctx, secretName)
	if err != nil {
		return fmt.Errorf("failed to get lemonsqueezy webhook secret: %w", err)
	}
	if sigHeader == "" {
		return fmt.Errorf("missing X-Signature header")
	}
	if len(sigHeader) > MaxSigHeaderBytes {
		return fmt.Errorf("X-Signature header too long")
	}
	// Tolerate the optional `sha256=` prefix that some webhook UI
	// tools (and a few proxies) prepend to hex signatures.
	sigHeader = strings.TrimPrefix(strings.TrimSpace(sigHeader), "sha256=")
	for _, secret := range splitRotationSecrets(rawSecret) {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expected := hex.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(sigHeader), []byte(expected)) {
			return nil
		}
	}
	return fmt.Errorf("lemonsqueezy signature mismatch")
}
