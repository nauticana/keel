package crypto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundtrip(t *testing.T) {
	key := mustKey(t)
	for _, p := range [][]byte{nil, []byte(""), []byte("x"), []byte("hello world")} {
		sealed, err := Seal(key, p)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if !IsSealed(sealed) {
			t.Fatalf("IsSealed false for %q", sealed)
		}
		got, ok := Open(key, sealed)
		if !ok || !bytes.Equal(got, p) {
			t.Fatalf("roundtrip: got %q ok=%v want %q", got, ok, p)
		}
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	sealed, _ := Seal(mustKey(t), []byte("secret"))
	if _, ok := Open(mustKey(t), sealed); ok {
		t.Fatal("Open should fail with wrong key")
	}
}

func TestOpenRejectsLegacyPlaintext(t *testing.T) {
	if _, ok := Open(mustKey(t), "plain-old-value"); ok {
		t.Fatal("Open should return false for non-prefixed input")
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	key := mustKey(t)
	sealed, _ := Seal(key, []byte("hello"))
	tampered := sealed[:len(sealed)-2] + "AA"
	if _, ok := Open(key, tampered); ok {
		t.Fatal("Open should fail on tampered ciphertext")
	}
}

func TestNonceIsRandom(t *testing.T) {
	key := mustKey(t)
	a, _ := Seal(key, []byte("same"))
	b, _ := Seal(key, []byte("same"))
	if a == b {
		t.Fatal("two Seals of identical plaintext produced identical ciphertext")
	}
}

func TestDecodeKEK(t *testing.T) {
	if _, err := DecodeKEK(strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("valid 64-hex KEK rejected: %v", err)
	}
	if _, err := DecodeKEK("short"); err == nil {
		t.Fatal("short KEK accepted")
	}
	if _, err := DecodeKEK("zz" + strings.Repeat("ab", 31)); err == nil {
		t.Fatal("non-hex KEK accepted")
	}
}
