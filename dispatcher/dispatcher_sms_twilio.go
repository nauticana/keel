package dispatcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

// twilioSendURL is the Twilio Messages API endpoint. The %s slot is the
// account SID (also the basic-auth username).
const twilioSendURL = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json"

// newTwilioSMSDispatcher builds an SMS dispatcher backed by Twilio's Messages
// API. Twilio's Messaging Service (SMSServiceSID) picks the correct sender
// (CA long code, US 10DLC, UK/EU alphanumeric, …) per destination from the
// senders attached in the Twilio console — adding a region is console-only.
//
// Required:
//   - secret `sms_account_sid` — Twilio account SID (basic-auth username)
//   - secret `sms_auth_token`  — Twilio auth token (basic-auth password)
//   - config `sms_service_sid` — Messaging Service SID (MGxxxxxxxx...)
func newTwilioSMSDispatcher(ctx context.Context, secrets secret.SecretProvider, users port.RecipientResolver, journal logger.ApplicationLogger) (port.MessageDispatcher, error) {
	accountSID, err := secrets.GetSecret(ctx, "sms_account_sid")
	if err != nil {
		return nil, fmt.Errorf("twilio: get sms_account_sid: %w", err)
	}
	accountSID = strings.TrimSpace(accountSID)
	if accountSID == "" {
		return nil, fmt.Errorf("twilio: sms_account_sid is empty")
	}
	token, err := secrets.GetSecret(ctx, "sms_auth_token")
	if err != nil {
		return nil, fmt.Errorf("twilio: get sms_auth_token: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("twilio: sms_auth_token is empty")
	}
	msgSvc := strings.TrimSpace(common.Config().SMSServiceSID)
	if msgSvc == "" {
		return nil, fmt.Errorf("twilio: sms_service_sid not set")
	}

	hc := smsHTTPClient()
	endpoint := fmt.Sprintf(twilioSendURL, accountSID)
	post := func(ctx context.Context, to, body string) error {
		form := url.Values{}
		form.Set("To", to)
		form.Set("Body", body)
		form.Set("MessagingServiceSid", msgSvc)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.SetBasicAuth(accountSID, token)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

	return &smsDispatcher{users: users, journal: journal, name: "twilio", postFn: post}, nil
}
