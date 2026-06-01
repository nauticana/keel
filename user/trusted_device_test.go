package user

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHashDeviceSecretMatchesSHA256Hex(t *testing.T) {
	secret := "abc-deadbeef-1234"
	want := func() string {
		s := sha256.Sum256([]byte(secret))
		return hex.EncodeToString(s[:])
	}()
	if got := hashDeviceSecret(secret); got != want {
		t.Fatalf("hashDeviceSecret = %q, want %q", got, want)
	}
	if len(want) != 64 {
		t.Fatalf("hex SHA256 expected len 64, got %d", len(want))
	}
}

func TestHashDeviceSecretDeterministic(t *testing.T) {
	a := hashDeviceSecret("same-input")
	b := hashDeviceSecret("same-input")
	if a != b {
		t.Fatal("hash should be deterministic for identical input")
	}
}

func TestHashDeviceSecretDistinctInputs(t *testing.T) {
	if hashDeviceSecret("a") == hashDeviceSecret("b") {
		t.Fatal("distinct inputs produced identical hashes")
	}
}
