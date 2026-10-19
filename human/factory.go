package human

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

// New builds the verifier named by mode with the given secret: turnstile,
// hcaptcha or recaptcha. noop or empty returns (nil, nil), which handlers read
// as "no check".
func New(mode, secretValue string, timeout time.Duration) (port.HumanVerifier, error) {
	var endpoint string
	switch strings.TrimSpace(mode) {
	case "", "noop":
		return nil, nil
	case "turnstile":
		endpoint = TurnstileEndpoint
	case "hcaptcha":
		endpoint = HCaptchaEndpoint
	case "recaptcha":
		endpoint = ReCAPTCHAEndpoint
	default:
		return nil, fmt.Errorf("human: unknown human_verifier_mode %q", mode)
	}
	if strings.TrimSpace(secretValue) == "" {
		return nil, fmt.Errorf("human: the %s secret is empty", mode)
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("human: human_verifier_timeout must be positive")
	}
	return &SiteVerify{Endpoint: endpoint, Secret: secretValue, Client: &http.Client{Timeout: timeout}}, nil
}

// NewFromConfig reads human_verifier_mode, human_verifier_timeout and the secret
// named by human_verifier_secret.
func NewFromConfig(ctx context.Context, secrets secret.SecretProvider) (port.HumanVerifier, error) {
	cfg := config.Config()
	mode := strings.TrimSpace(cfg.HumanVerifierMode)
	if mode == "" || mode == "noop" {
		return nil, nil
	}
	if secrets == nil {
		return nil, fmt.Errorf("human: a secret provider is required when human_verifier_mode=%s", mode)
	}
	value, err := secrets.GetSecret(ctx, cfg.HumanVerifierSecret)
	if err != nil {
		return nil, fmt.Errorf("human: read secret %s: %w", cfg.HumanVerifierSecret, err)
	}
	return New(mode, value, cfg.HumanVerifierTimeout)
}
