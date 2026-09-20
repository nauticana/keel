package dispatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

// quoSendURL is the Quo (formerly OpenPhone) Messages API v1 endpoint.
const quoSendURL = "https://api.quo.com/v1/messages"

// newQuoSMSDispatcher builds an SMS dispatcher backed by Quo's Messages API.
//
// Quo has no sender-pool object: `from` is a single sender, either a phone
// number id (PN…) or the number itself in E.164, so sms_service_sid carries
// that sender here. One message is posted per recipient even though the API
// takes a `to` array, keeping the per-recipient error semantics the shared
// smsDispatcher expects.
//
// Required:
//   - secret `sms_auth_token`  — Quo API key. sms_account_sid is unused.
//   - config `sms_service_sid` — sender: phone number id (PN…) or E.164 number
func newQuoSMSDispatcher(ctx context.Context, secrets secret.SecretProvider, users port.RecipientResolver, journal logger.ApplicationLogger) (port.MessageDispatcher, error) {
	return newQuoSMSDispatcherWithClient(ctx, secrets, users, journal, quoSendURL, smsHTTPClient())
}

func newQuoSMSDispatcherWithClient(ctx context.Context, secrets secret.SecretProvider, users port.RecipientResolver, journal logger.ApplicationLogger, endpoint string, hc *http.Client) (port.MessageDispatcher, error) {
	apiKey, err := secrets.GetSecret(ctx, "sms_auth_token")
	if err != nil {
		return nil, fmt.Errorf("quo: get sms_auth_token: %w", err)
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, fmt.Errorf("quo: sms_auth_token is empty")
	}
	from := strings.TrimSpace(config.Config().SMSServiceSID)
	if from == "" {
		return nil, fmt.Errorf("quo: sms_service_sid not set")
	}

	post := func(ctx context.Context, to, body string) error {
		payload, err := json.Marshal(map[string]any{
			"from":    from,
			"to":      []string{to},
			"content": body,
		})
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", apiKey) // raw key, not a Bearer token
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("send: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			_, _ = io.Copy(io.Discard, resp.Body) // drain for keep-alive reuse
			return nil
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return &smsDispatcher{users: users, journal: journal, name: "quo", postFn: post}, nil
}
