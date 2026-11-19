package entitlement

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
)

// Verifier checks license files offline against the public keys it is built with, normally embedded in the
// installation's binaries. It decides only whether a file is genuine and well formed; StateAt and Admits decide
// what the document allows at a moment.
type Verifier struct {
	keys map[string]*rsa.PublicKey
}

// NewVerifier returns a verifier over one or more PEM public keys, PKIX "PUBLIC KEY" or PKCS#1 "RSA PUBLIC KEY".
// Several keys let a file signed before a key rotation still verify.
func NewVerifier(publicKeys ...[]byte) (*Verifier, error) {
	v := &Verifier{keys: map[string]*rsa.PublicKey{}}
	for _, text := range publicKeys {
		public, err := parsePublicKey(text)
		if err != nil {
			return nil, err
		}
		id, err := KeyID(public)
		if err != nil {
			return nil, err
		}
		v.keys[id] = public
	}
	if len(v.keys) == 0 {
		return nil, fmt.Errorf("%w: a verifier needs a public key", ErrUnknownKey)
	}
	return v, nil
}

// Verify reads a license file and returns its document once the signature matches a known key, the payload is in
// the canonical form, and the document is valid. It does not read the clock.
func (v *Verifier) Verify(data []byte) (Document, error) {
	f, err := ParseFile(data)
	if err != nil {
		return Document{}, err
	}
	if f.Algorithm != Algorithm {
		return Document{}, fmt.Errorf("%w: algorithm %q", ErrUnsupported, f.Algorithm)
	}
	public, ok := v.keys[f.KeyID]
	if !ok {
		return Document{}, fmt.Errorf("%w: %s", ErrUnknownKey, f.KeyID)
	}
	payload, err := f.payload()
	if err != nil {
		return Document{}, err
	}
	signature, err := f.signature()
	if err != nil {
		return Document{}, err
	}
	digest := sha256.Sum256(payload)
	if err := rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		return Document{}, ErrSignature
	}
	var doc Document
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("%w: document: %v", ErrMalformed, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Document{}, fmt.Errorf("%w: data after the document", ErrMalformed)
	}
	canonical, err := doc.Encode()
	if err != nil {
		return Document{}, err
	}
	if !bytes.Equal(canonical, payload) {
		return Document{}, fmt.Errorf("%w: the document is not in canonical form", ErrMalformed)
	}
	return doc, nil
}

func parsePublicKey(text []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(text)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block in the public key", ErrMalformed)
	}
	switch block.Type {
	case "RSA PUBLIC KEY":
		public, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: public key: %v", ErrMalformed, err)
		}
		return public, nil
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: public key: %v", ErrMalformed, err)
		}
		public, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: the public key is a %T, not an RSA key", ErrUnsupported, parsed)
		}
		return public, nil
	}
	return nil, fmt.Errorf("%w: PEM block %q is not a public key", ErrMalformed, block.Type)
}
