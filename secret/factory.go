package secret

import (
	"context"
	"fmt"
	"log"

	"github.com/nauticana/keel/common"
)

func NewSecretProvider(ctx context.Context) (SecretProvider, error) {
	switch *common.SecretMode {
	case "local":
		return &SecretProviderLocal{Filename: *common.Keystore}, nil
	case "gsm":
		return NewSecretProviderGSM(ctx)
	case "aws":
		return NewSecretProviderAWS(ctx)
	default:
		return nil, fmt.Errorf("unknown secret_mode: %s", *common.SecretMode)
	}
}

// MustGet returns the value of the named secret or terminates the
// process via log.Fatalf when the lookup fails. Use this only at
// process boot for genuinely-required keys (Stripe secret key, JWT
// secret, DB password) where there is no useful runtime fallback —
// every consumer was previously reimplementing
//
//	v, err := secrets.GetSecret(ctx, name)
//	if err != nil { log.Fatalf(...) }
//
// for those values; this helper dedups the pattern and matches the
// existing handler.MustRequireTrustedProxyCIDR precedent (downstream
// feedback v0.5.1-G).
//
// NEVER call MustGet from a hot request path. A transient secret-
// provider outage would Fatalf the whole process for one bad lookup.
// For runtime / per-request reads keep using SecretProvider.GetSecret
// and surface the error to the caller.
func MustGet(ctx context.Context, p SecretProvider, name string) string {
	v, err := p.GetSecret(ctx, name)
	if err != nil {
		log.Fatalf("secret %q: %v", name, err)
	}
	return v
}
