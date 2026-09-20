package client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const (
	ShopifyWebhookHMACHeader  = "X-Shopify-Hmac-Sha256"
	ShopifyWebhookTopicHeader = "X-Shopify-Topic"
)

var ErrShopifyWebhookSignature = errors.New("shopify webhook signature invalid")

// VerifyShopifyWebhook checks the base64 HMAC-SHA256 of the raw body under the
// app's client secret.
func VerifyShopifyWebhook(body []byte, signature, secret string) error {
	given, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(given) == 0 || secret == "" {
		return ErrShopifyWebhookSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), given) {
		return ErrShopifyWebhookSignature
	}
	return nil
}
