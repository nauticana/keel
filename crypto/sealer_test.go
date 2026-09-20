package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

type mapSecrets map[string]string

func (m mapSecrets) GetSecret(_ context.Context, name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", errors.New("secret not found")
	}
	return v, nil
}

func testKEK() []byte { return bytes.Repeat([]byte{0xA7}, 32) }

func TestDecodeKEKAcceptsHexAndBase64(t *testing.T) {
	key := testKEK()
	for name, encoded := range map[string]string{
		"hex":           hex.EncodeToString(key),
		"hex upper":     strings.ToUpper(hex.EncodeToString(key)),
		"hex spaced":    "  " + hex.EncodeToString(key) + "\n",
		"base64":        base64.StdEncoding.EncodeToString(key),
		"base64 raw":    base64.RawStdEncoding.EncodeToString(key),
		"base64 url":    base64.URLEncoding.EncodeToString(key),
		"base64 rawurl": base64.RawURLEncoding.EncodeToString(key),
	} {
		got, err := DecodeKEK(encoded)
		if err != nil || !bytes.Equal(got, key) {
			t.Errorf("%s: got %x, err %v", name, got, err)
		}
	}
}

func TestDecodeKEKRejectsWrongLengthAndGarbage(t *testing.T) {
	for name, encoded := range map[string]string{
		"empty":        "",
		"short hex":    hex.EncodeToString(make([]byte, 16)),
		"long hex":     hex.EncodeToString(make([]byte, 33)),
		"short base64": base64.StdEncoding.EncodeToString(make([]byte, 31)),
		"garbage":      "not a key!",
	} {
		if _, err := DecodeKEK(encoded); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSealerRoundTripAndEnvelope(t *testing.T) {
	secrets := mapSecrets{"tax_id_kek": base64.StdEncoding.EncodeToString(testKEK())}
	s, err := NewSealer(context.Background(), secrets, "tax_id_kek")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.SealBytes("12-3456789")
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(string(sealed)) || strings.Contains(string(sealed), "12-3456789") {
		t.Fatalf("sealed = %q", sealed)
	}
	plain, err := s.Open(string(sealed))
	if err != nil || plain != "12-3456789" {
		t.Fatalf("open = %q, %v", plain, err)
	}
	if direct, ok := Open(testKEK(), string(sealed)); !ok || string(direct) != "12-3456789" {
		t.Fatal("envelope is not the package-level Seal format")
	}
}

func TestSealerOpenRejectsForeignKey(t *testing.T) {
	a, _ := NewSealer(context.Background(), mapSecrets{"k": hex.EncodeToString(testKEK())}, "k")
	b, _ := NewSealer(context.Background(), mapSecrets{"k": hex.EncodeToString(bytes.Repeat([]byte{1}, 32))}, "k")
	sealed, _ := a.Seal("v")
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("opened with the wrong key")
	}
}

func TestLoadKEKErrorsNameSecretNotValue(t *testing.T) {
	if _, err := LoadKEK(context.Background(), nil, "k"); err == nil {
		t.Fatal("nil secret provider accepted")
	}
	if _, err := LoadKEK(context.Background(), mapSecrets{}, "  "); err == nil {
		t.Fatal("empty secret name accepted")
	}
	if _, err := LoadKEK(context.Background(), mapSecrets{}, "missing_kek"); err == nil || !strings.Contains(err.Error(), "missing_kek") {
		t.Fatalf("err = %v", err)
	}
	bad := "zz-not-a-key-zz"
	_, err := LoadKEK(context.Background(), mapSecrets{"k": bad}, "k")
	if err == nil || strings.Contains(err.Error(), bad) {
		t.Fatalf("err = %v", err)
	}
}
