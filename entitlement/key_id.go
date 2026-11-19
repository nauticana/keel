package entitlement

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// MinKeyBits is the shortest RSA modulus this package signs with or verifies against.
const MinKeyBits = 2048

// KeyID names a public key: the first 16 bytes of the SHA-256 of its PKIX encoding, in hex. A verifier holding
// several keys, during a rotation, picks the one a file names.
func KeyID(public *rsa.PublicKey) (string, error) {
	if public == nil || public.N == nil {
		return "", fmt.Errorf("%w: no key", ErrWeakKey)
	}
	if public.N.BitLen() < MinKeyBits {
		return "", fmt.Errorf("%w: %d bits, at least %d are required", ErrWeakKey, public.N.BitLen(), MinKeyBits)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:16]), nil
}

// PublicKeyPEM encodes a public key as a PEM "PUBLIC KEY" block, the form a verifier is given.
func PublicKeyPEM(public *rsa.PublicKey) ([]byte, error) {
	if _, err := KeyID(public); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
