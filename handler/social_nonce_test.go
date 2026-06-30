package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/cache"
)

func issueNonce(t *testing.T, h *SocialLoginHandler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.LoginSocial(rec, httptest.NewRequest(http.MethodGet, "/login/social", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("issue: status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("nonce response Cache-Control = %q, want no-store", cc)
	}
	var resp struct {
		Data struct{ Nonce string } `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Data.Nonce
}

func TestSocialNonce_SingleUseAndReplay(t *testing.T) {
	c := cache.NewMemoryCacheService()
	defer c.Close()
	h := &SocialLoginHandler{NonceCache: c}

	nonce := issueNonce(t, h)
	if nonce == "" {
		t.Fatal("issued nonce is empty")
	}
	ctx := context.Background()
	if !h.consumeSocialNonce(ctx, nonce) {
		t.Fatal("first consume should succeed")
	}
	if h.consumeSocialNonce(ctx, nonce) {
		t.Fatal("replay must be rejected")
	}
}

func TestSocialNonce_AppleSHA256Accepted(t *testing.T) {
	c := cache.NewMemoryCacheService()
	defer c.Close()
	h := &SocialLoginHandler{NonceCache: c}

	nonce := issueNonce(t, h)
	sum := sha256.Sum256([]byte(nonce))
	if !h.consumeSocialNonce(context.Background(), hex.EncodeToString(sum[:])) {
		t.Fatal("Apple's SHA-256 nonce should be accepted")
	}
}

func TestConsumeSocialNonce_EmptyAndUnknown(t *testing.T) {
	c := cache.NewMemoryCacheService()
	defer c.Close()
	h := &SocialLoginHandler{NonceCache: c}
	ctx := context.Background()
	if h.consumeSocialNonce(ctx, "") {
		t.Fatal("empty nonce must be rejected")
	}
	// An unknown nonce must stay rejected on EVERY submission, not just the first.
	for i := 0; i < 4; i++ {
		if h.consumeSocialNonce(ctx, "deadbeef") {
			t.Fatalf("unknown nonce accepted on submission %d", i+1)
		}
	}
}

func TestSocialNonce_NoCacheReturnsEmpty(t *testing.T) {
	h := &SocialLoginHandler{}
	if n := issueNonce(t, h); n != "" {
		t.Fatalf("nil cache should yield empty nonce, got %q", n)
	}
}
