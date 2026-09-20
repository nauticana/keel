package client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"testing"
)

func TestCanonicalShopDomain(t *testing.T) {
	ok := map[string]string{
		"mystore.myshopify.com":               "mystore.myshopify.com",
		"MyStore.myshopify.com":               "mystore.myshopify.com",
		"https://mystore.myshopify.com":       "mystore.myshopify.com",
		"https://mystore.myshopify.com/admin": "mystore.myshopify.com",
	}
	for in, want := range ok {
		got, err := CanonicalShopDomain(in)
		if err != nil || got != want {
			t.Errorf("CanonicalShopDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "evil.com", "evil.com#.myshopify.com", "mystore.myshopify.com.evil.com", "notashop"}
	for _, in := range bad {
		if got, err := CanonicalShopDomain(in); err == nil {
			t.Errorf("CanonicalShopDomain(%q) = %q, want error", in, got)
		}
	}
}

func TestValidateShopifyHMAC(t *testing.T) {
	secret := "app-secret"
	q := url.Values{"code": {"abc"}, "shop": {"mystore.myshopify.com"}, "timestamp": {"1700000000"}}
	// Build the valid HMAC exactly as Shopify does (sorted key=value joined by &).
	msg := "code=abc&shop=mystore.myshopify.com&timestamp=1700000000"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	q.Set("hmac", hex.EncodeToString(mac.Sum(nil)))
	if err := validateShopifyHMAC(q, secret); err != nil {
		t.Fatalf("valid hmac rejected: %v", err)
	}
	// Tamper: a changed param invalidates the signature.
	q.Set("code", "tampered")
	if err := validateShopifyHMAC(q, secret); err == nil {
		t.Fatal("tampered query should fail hmac")
	}
	// Missing hmac is rejected.
	q2 := url.Values{"shop": {"mystore.myshopify.com"}}
	if err := validateShopifyHMAC(q2, secret); err == nil {
		t.Fatal("missing hmac should fail")
	}
}

func TestVerifyShopifyWebhook(t *testing.T) {
	body := []byte(`{"shop_id":1}`)
	mac := hmac.New(sha256.New, []byte("app-secret"))
	mac.Write(body)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if err := VerifyShopifyWebhook(body, sig, "app-secret"); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	for name, tc := range map[string][3]string{
		"tampered body": {`{"shop_id":2}`, sig, "app-secret"},
		"wrong secret":  {string(body), sig, "other"},
		"missing":       {string(body), "", "app-secret"},
		"not base64":    {string(body), "%%%", "app-secret"},
		"empty secret":  {string(body), sig, ""},
	} {
		if err := VerifyShopifyWebhook([]byte(tc[0]), tc[1], tc[2]); !errors.Is(err, ErrShopifyWebhookSignature) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
