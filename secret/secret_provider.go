package secret

import "context"

type SecretProvider interface {
	GetSecret(ctx context.Context, path string) (string, error)
}
