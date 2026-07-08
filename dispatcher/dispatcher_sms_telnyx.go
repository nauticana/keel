package dispatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

// telnyxSendURL is the Telnyx Messages API v2 endpoint.
const telnyxSendURL = "https://api.telnyx.com/v2/messages"

// newTelnyxSMSDispatcher builds an SMS dispatcher backed by Telnyx's Messages
// API — a cheaper Twilio-alternative with the same sender-pool model: the
// Messaging Profile (SMSServiceSID) selects the sender per destination.
//
// This deliberately uses Telnyx's number-pool variant (messaging_profile_id +
// to + text), not the direct-number variant (from + to + text): the sender is
// chosen by the profile, matching the Twilio adapter's sender-pool semantics.
//
// Required:
//   - secret `sms_auth_token`  — Telnyx API key (Bearer). sms_account_sid is unused.
//   - config `sms_service_sid` — Messaging Profile ID
func newTelnyxSMSDispatcher(ctx context.Context, secrets secret.SecretProvider, users port.RecipientResolver, journal logger.ApplicationLogger) (port.MessageDispatcher, error) {
	apiKey, err := secrets.GetSecret(ctx, "sms_auth_token")
	if err != nil {
		return nil, fmt.Errorf("telnyx: get sms_auth_token: %w", err)
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, fmt.Errorf("telnyx: sms_auth_token is empty")
	}
	profileID := strings.TrimSpace(common.Config().SMSServiceSID)
	if profileID == "" {
		return nil, fmt.Errorf("telnyx: sms_service_sid not set")
	}

	hc := smsHTTPClient()
	post := func(ctx context.Context, to, body string) error {
		payload, err := json.Marshal(map[string]string{
			"messaging_profile_id": profileID,
			"to":                   to,
			"text":                 body,
		})
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, telnyxSendURL, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
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

	return &smsDispatcher{users: users, journal: journal, name: "telnyx", postFn: post}, nil
}
