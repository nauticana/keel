package secret

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type SecretProvider interface {
	GetSecret(ctx context.Context, path string) (string, error)
}

// PutSecret creates the secret or makes value its current version; earlier
// versions stay in backends that keep them.
type SecretRWProvider interface {
	SecretProvider
	PutSecret(ctx context.Context, path string, value string) error
}

var ErrInvalidSecretWrite = errors.New("invalid secret write")

// GetSecret trims, so a blank value could never be read back.
func validatePut(path, value string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: empty path", ErrInvalidSecretWrite)
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: blank value for %s", ErrInvalidSecretWrite, path)
	}
	return nil
}
