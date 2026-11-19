package entitlement

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

const (
	// Algorithm is RSA-PSS with SHA-256 and a salt the length of the hash, the only one this version signs and reads.
	Algorithm = "PS256"
	// MaxFileBytes bounds a license file a verifier reads.
	MaxFileBytes = 64 << 10
)

// File is a license as it is stored and shipped: the canonical document, base64url without padding, the signature
// over exactly those bytes, and the signing key's id. A reformatted file still verifies; a changed payload does not.
type File struct {
	Payload   string `json:"payload"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// ParseFile reads a license file strictly: one JSON object of exactly these fields and nothing after it.
func ParseFile(data []byte) (File, error) {
	if len(data) > MaxFileBytes {
		return File{}, fmt.Errorf("%w: file exceeds %d bytes", ErrMalformed, MaxFileBytes)
	}
	var f File
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return File{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return File{}, fmt.Errorf("%w: data after the file", ErrMalformed)
	}
	if f.Payload == "" || f.KeyID == "" || f.Signature == "" {
		return File{}, fmt.Errorf("%w: payload, key_id, and signature are required", ErrMalformed)
	}
	return f, nil
}

// Marshal returns the file as indented JSON with a final newline.
func (f File) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// payload returns the signed bytes.
func (f File) payload() ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(f.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	return data, nil
}

// signature returns the signature bytes.
func (f File) signature() ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(f.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}
	return data, nil
}
