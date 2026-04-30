package secret

import (
	"context"
	"fmt"

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
