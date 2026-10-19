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

// Settings tunes a verifier beyond its endpoint and secret. MinScore and Action
// apply to recaptcha_v3 only; Hostnames applies to every mode when non-empty.
type Settings struct {
	Timeout   time.Duration
	MinScore  float64
	Action    string
	Hostnames []string
}

// New builds the verifier named by mode with the given secret: turnstile,
// hcaptcha, recaptcha or recaptcha_v3. noop or empty returns (nil, nil), which
// handlers read as "no check".
func New(mode, secretValue string, s Settings) (port.HumanVerifier, error) {
	v := &SiteVerify{Secret: secretValue, Hostnames: s.Hostnames}
	switch mode = strings.TrimSpace(mode); mode {
	case "", "noop":
		return nil, nil
	case "turnstile":
		v.Endpoint = TurnstileEndpoint
	case "hcaptcha":
		v.Endpoint = HCaptchaEndpoint
	case "recaptcha":
		v.Endpoint = ReCAPTCHAEndpoint
	case "recaptcha_v3":
		v.Endpoint, v.MinScore, v.Action = ReCAPTCHAEndpoint, s.MinScore, strings.TrimSpace(s.Action)
		if !(s.MinScore > 0 && s.MinScore <= 1) || v.Action == "" {
			return nil, fmt.Errorf("human: recaptcha_v3 needs human_verifier_min_score in (0,1] and human_verifier_action")
		}
	default:
		return nil, fmt.Errorf("human: unknown human_verifier_mode %q", mode)
	}
	if strings.TrimSpace(secretValue) == "" {
		return nil, fmt.Errorf("human: the %s secret is empty", mode)
	}
	if s.Timeout <= 0 {
		return nil, fmt.Errorf("human: human_verifier_timeout must be positive")
	}
	v.Client = &http.Client{Timeout: s.Timeout}
	return v, nil
}

// NewFromConfig reads the human_verifier_* flags and the secret named by
// human_verifier_secret.
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
	var hosts []string
	for _, h := range strings.Split(cfg.HumanVerifierHostnames, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return New(mode, value, Settings{Timeout: cfg.HumanVerifierTimeout, MinScore: cfg.HumanVerifierMinScore, Action: cfg.HumanVerifierAction, Hostnames: hosts})
}
