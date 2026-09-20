// Package reference holds clients for public reference-data APIs: Chrome UX
// Report field data, Google Knowledge Graph and Wikidata entity search. All
// ride common.RequestJSON, so outbound limits and typed status errors apply.
package reference

import (
	"context"
	"errors"
	"fmt"

	"github.com/nauticana/keel/secret"
)

// ErrNoAPIKey means the client has no key to call with — "not tried", as
// opposed to "tried and found nothing".
var ErrNoAPIKey = errors.New("reference: no API key configured")

const googleAPIKeyHeader = "X-Goog-Api-Key"

// APIKey names a keystore secret holding a provider API key.
type APIKey struct {
	Secrets    secret.SecretProvider
	SecretName string
}

func (k APIKey) headers(ctx context.Context) (map[string]string, error) {
	if k.Secrets == nil || k.SecretName == "" {
		return nil, ErrNoAPIKey
	}
	key, err := k.Secrets.GetSecret(ctx, k.SecretName)
	if err != nil {
		return nil, fmt.Errorf("reference: read %s: %w", k.SecretName, err)
	}
	if key == "" {
		return nil, ErrNoAPIKey
	}
	return map[string]string{googleAPIKeyHeader: key}, nil
}
