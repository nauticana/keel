package crypto

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nauticana/keel/secret"
)

// LoadKEK fetches and decodes the AES-256 KEK stored at secretName. Errors name
// the secret, never its value.
func LoadKEK(ctx context.Context, secrets secret.SecretProvider, secretName string) ([]byte, error) {
	if secrets == nil {
		return nil, errors.New("load KEK: nil secret provider")
	}
	if strings.TrimSpace(secretName) == "" {
		return nil, errors.New("load KEK: empty secret name")
	}
	raw, err := secrets.GetSecret(ctx, secretName)
	if err != nil {
		return nil, fmt.Errorf("fetch KEK %q: %w", secretName, err)
	}
	key, err := DecodeKEK(raw)
	if err != nil {
		return nil, fmt.Errorf("KEK %q: %w", secretName, err)
	}
	return key, nil
}

// Sealer seals and opens "enc:v1:" envelopes under one KEK.
type Sealer struct {
	key []byte
}

// NewSealer loads the KEK at secretName once; pick one secret name per purpose
// at composition time.
func NewSealer(ctx context.Context, secrets secret.SecretProvider, secretName string) (*Sealer, error) {
	key, err := LoadKEK(ctx, secrets, secretName)
	if err != nil {
		return nil, err
	}
	return &Sealer{key: key}, nil
}

func (s *Sealer) Seal(plain string) (string, error) { return Seal(s.key, []byte(plain)) }

func (s *Sealer) Open(sealed string) (string, error) { return DecryptToken(s.key, sealed) }

// SealBytes has the func(string) ([]byte, error) shape of byte-column seal
// hooks such as handler.PayoutHandler.SealTaxID.
func (s *Sealer) SealBytes(plain string) ([]byte, error) {
	sealed, err := s.Seal(plain)
	if err != nil {
		return nil, err
	}
	return []byte(sealed), nil
}
