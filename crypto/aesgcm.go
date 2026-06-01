// Package crypto provides at-rest encryption primitives for keel services
// (TOTP seeds, refresh tokens, secret-manager-backed vault values, etc.).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// sealPrefix tags ciphertext so callers can distinguish encrypted values
// from legacy plaintext during a migration window.
const sealPrefix = "enc:v1:"

// DecodeKEK parses a 32-byte AES-256 key from its 64-char hex form.
func DecodeKEK(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("KEK must be 32 bytes (64 hex chars)")
	}
	return key, nil
}

// Seal returns "enc:v1:" + base64(nonce || AES-256-GCM(plain)).
func Seal(key, plain []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plain, nil)
	return sealPrefix + base64.RawStdEncoding.EncodeToString(ct), nil
}

// Open reverses Seal. (nil, false) on prefix mismatch, decode error, wrong
// key, or tampered ciphertext — callers can treat that as legacy plaintext.
func Open(key []byte, sealed string) ([]byte, bool) {
	if !strings.HasPrefix(sealed, sealPrefix) {
		return nil, false
	}
	raw, err := base64.RawStdEncoding.DecodeString(sealed[len(sealPrefix):])
	if err != nil {
		return nil, false
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, false
	}
	if len(raw) < gcm.NonceSize() {
		return nil, false
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, false
	}
	return plain, true
}

// IsSealed reports whether s carries the Seal envelope prefix.
func IsSealed(s string) bool { return strings.HasPrefix(s, sealPrefix) }

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
