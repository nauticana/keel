package entitlement

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// Signer signs license documents with one RSA private key. The vendor's portal holds it; the key never leaves the
// secret store it is read from.
type Signer struct {
	key   *rsa.PrivateKey
	keyID string
}

// NewSigner returns a signer over key, refusing one shorter than MinKeyBits or inconsistent.
func NewSigner(key *rsa.PrivateKey) (*Signer, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: no key", ErrWeakKey)
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("entitlement: signing key: %w", err)
	}
	id, err := KeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, keyID: id}, nil
}

// NewSignerFromPEM reads an RSA private key from a PEM block, PKCS#8 "PRIVATE KEY" or PKCS#1 "RSA PRIVATE KEY".
func NewSignerFromPEM(text []byte) (*Signer, error) {
	block, _ := pem.Decode(text)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block in the signing key", ErrMalformed)
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: signing key: %v", ErrMalformed, err)
		}
		key = parsed
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: signing key: %v", ErrMalformed, err)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: the signing key is a %T, not an RSA key", ErrUnsupported, parsed)
		}
		key = rsaKey
	default:
		return nil, fmt.Errorf("%w: PEM block %q is not a private key", ErrMalformed, block.Type)
	}
	return NewSigner(key)
}

// KeyID names the signer's public key.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKeyPEM is the public key an installation embeds to verify this signer's files.
func (s *Signer) PublicKeyPEM() ([]byte, error) { return PublicKeyPEM(&s.key.PublicKey) }

// Sign encodes the document canonically and signs it.
func (s *Signer) Sign(doc Document) (File, error) {
	payload, err := doc.Encode()
	if err != nil {
		return File{}, err
	}
	digest := sha256.Sum256(payload)
	signature, err := rsa.SignPSS(rand.Reader, s.key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return File{}, fmt.Errorf("entitlement: sign: %w", err)
	}
	return File{
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Algorithm: Algorithm,
		KeyID:     s.keyID,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}
