package human

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/nauticana/keel/port"
)

// Provider siteverify endpoints. All take the same form fields and answer with
// the same `success` field, so one client covers them.
const (
	TurnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	HCaptchaEndpoint  = "https://api.hcaptcha.com/siteverify"
	ReCAPTCHAEndpoint = "https://www.google.com/recaptcha/api/siteverify"
)

const maxSiteVerifyResponse = 64 << 10

// SiteVerify checks a challenge token against a siteverify endpoint.
type SiteVerify struct {
	Endpoint string
	Secret   string
	// Client bounds the call; it must carry a timeout.
	Client *http.Client
	// MinScore refuses a reCAPTCHA v3 score below it when positive; Action and
	// Hostnames, when set, must match what the provider echoes.
	MinScore  float64
	Action    string
	Hostnames []string
}

var _ port.HumanVerifier = (*SiteVerify)(nil)

// Verify posts the token and the client address to the endpoint. A blank token is
// ErrChallengeRequired without a call; a provider that cannot be reached or
// answers unexpectedly is ErrChallengeUnavailable; a rejected token, or one whose
// score, action or hostname is not accepted, is ErrChallengeFailed.
func (v *SiteVerify) Verify(ctx context.Context, token, remoteIP string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return port.ErrChallengeRequired
	}
	if v.Client == nil || v.Endpoint == "" || v.Secret == "" {
		return fmt.Errorf("%w: verifier is not configured", port.ErrChallengeUnavailable)
	}
	form := url.Values{"secret": {v.Secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %v", port.ErrChallengeUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.Client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", port.ErrChallengeUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", port.ErrChallengeUnavailable, resp.StatusCode)
	}
	var outcome struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
		Score      float64  `json:"score"`
		Action     string   `json:"action"`
		Hostname   string   `json:"hostname"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSiteVerifyResponse)).Decode(&outcome); err != nil {
		return fmt.Errorf("%w: %v", port.ErrChallengeUnavailable, err)
	}
	switch {
	case !outcome.Success:
		return fmt.Errorf("%w: %s", port.ErrChallengeFailed, strings.Join(outcome.ErrorCodes, ","))
	case v.MinScore > 0 && outcome.Score < v.MinScore:
		return fmt.Errorf("%w: score %.2f below %.2f", port.ErrChallengeFailed, outcome.Score, v.MinScore)
	case v.Action != "" && outcome.Action != v.Action:
		return fmt.Errorf("%w: action %q", port.ErrChallengeFailed, outcome.Action)
	case len(v.Hostnames) > 0 && !slices.ContainsFunc(v.Hostnames, func(h string) bool { return strings.EqualFold(h, outcome.Hostname) }):
		return fmt.Errorf("%w: hostname %q", port.ErrChallengeFailed, outcome.Hostname)
	}
	return nil
}
