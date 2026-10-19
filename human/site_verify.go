package human

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nauticana/keel/port"
)

// Provider siteverify endpoints. All three take the same form fields and answer
// with the same `success` field, so one client covers them.
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
}

var _ port.HumanVerifier = (*SiteVerify)(nil)

// Verify posts the token and the client address to the endpoint. A blank token is
// ErrChallengeRequired without a call; a provider that cannot be reached or
// answers unexpectedly is ErrChallengeUnavailable; a rejected token is
// ErrChallengeFailed with the provider's error codes.
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
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSiteVerifyResponse)).Decode(&outcome); err != nil {
		return fmt.Errorf("%w: %v", port.ErrChallengeUnavailable, err)
	}
	if !outcome.Success {
		return fmt.Errorf("%w: %s", port.ErrChallengeFailed, strings.Join(outcome.ErrorCodes, ","))
	}
	return nil
}
