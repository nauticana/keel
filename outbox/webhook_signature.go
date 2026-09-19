package outbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Header names and the v1 scheme follow the Standard Webhooks specification, so
// receivers can verify with an off-the-shelf library: the signature is
// base64(HMAC-SHA256(key, id + "." + timestamp + "." + body)).
const (
	HeaderWebhookID        = "Webhook-Id"
	HeaderWebhookTimestamp = "Webhook-Timestamp"
	HeaderWebhookSignature = "Webhook-Signature"

	signatureVersion = "v1"
	secretPrefix     = "whsec_"
)

var (
	ErrWebhookSecret    = errors.New("outbox: unusable webhook secret")
	ErrWebhookSignature = errors.New("outbox: webhook signature mismatch")
	ErrWebhookTimestamp = errors.New("outbox: webhook timestamp outside tolerance")
)

// signingKey accepts a "whsec_"-prefixed base64 key or a raw string key.
func signingKey(secret string) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("%w: empty", ErrWebhookSecret)
	}
	if encoded, ok := strings.CutPrefix(secret, secretPrefix); ok {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) == 0 {
			return nil, fmt.Errorf("%w: invalid base64 after %s", ErrWebhookSecret, secretPrefix)
		}
		return key, nil
	}
	return []byte(secret), nil
}

func signWebhook(key []byte, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return signatureVersion + "," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature is the receiver side of HTTPDispatcher. id, timestamp
// and signatureHeader are the three Webhook-* header values; body is the raw
// request body. Dedupe on id after verifying: it is stable across retries while
// the timestamp and signature are not.
func VerifyWebhookSignature(secret, id, timestamp string, body []byte, signatureHeader string, tolerance time.Duration, now time.Time) error {
	key, err := signingKey(secret)
	if err != nil {
		return err
	}
	sentUnix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrWebhookTimestamp, timestamp)
	}
	if age := now.Sub(time.Unix(sentUnix, 0)); age > tolerance || age < -tolerance {
		return ErrWebhookTimestamp
	}
	want := []byte(signWebhook(key, id, timestamp, body))
	for _, candidate := range strings.Fields(signatureHeader) {
		if hmac.Equal([]byte(candidate), want) {
			return nil
		}
	}
	return ErrWebhookSignature
}
