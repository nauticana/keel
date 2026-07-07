package dispatcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
	"github.com/nyaruka/phonenumbers"
)

// twilioSendURL is the Twilio Messages API endpoint. The %s slot is the
// account SID (also used as the basic-auth username).
const twilioSendURL = "https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json"

// TwilioSMSDispatcher delivers SMS via Twilio's Messages API. Implements
// port.MessageDispatcher so it plugs into LocalNotificationService on the
// "sms" channel alongside EmailDispatcher and any push/other dispatcher
// the consumer registers.
//
// Multi-region story: the dispatcher holds a single Twilio Messaging
// Service SID. Twilio's Messaging Service picks the correct sender
// (Canadian long code, US 10DLC, UK/EU alphanumeric, etc.) for each
// destination based on the senders attached to it in the Twilio console —
// no code change is required to add a region, only sender registration.
type TwilioSMSDispatcher struct {
	Users               port.RecipientResolver
	Journal             logger.ApplicationLogger
	accountSID          string
	authToken           string
	messagingServiceSID string
	http                *http.Client
}

// Compile-time check: TwilioSMSDispatcher satisfies port.MessageDispatcher.
var _ port.MessageDispatcher = (*TwilioSMSDispatcher)(nil)

// NewTwilioSMSDispatcher pulls credentials from the secret provider and the
// Messaging Service SID from the keel common flag twilio_messaging_service_sid.
// Returns an error when any required value is missing so callers can skip
// registering the SMS channel (matching the push-provider failure pattern).
//
// Required:
//   - secret `twilio_account_sid`  — Twilio account SID
//   - secret `twilio_auth_token`   — Twilio auth token
//   - flag   `twilio_messaging_service_sid` — MGxxxxxxxx...
//
// Pass the dispatcher's Users (a port.RecipientResolver) and Journal
// so it can resolve a userID to an E.164 phone via PhoneFor and so
// transport failures can be observed via the application logger.
func NewTwilioSMSDispatcher(ctx context.Context, secrets secret.SecretProvider, users port.RecipientResolver, journal logger.ApplicationLogger) (*TwilioSMSDispatcher, error) {
	sid, err := secrets.GetSecret(ctx, "twilio_account_sid")
	if err != nil {
		return nil, fmt.Errorf("twilio: get account_sid: %w", err)
	}
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return nil, fmt.Errorf("twilio: twilio_account_sid is empty")
	}
	token, err := secrets.GetSecret(ctx, "twilio_auth_token")
	if err != nil {
		return nil, fmt.Errorf("twilio: get auth_token: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("twilio: twilio_auth_token is empty")
	}
	msgSvc := strings.TrimSpace(common.Config().TwilioMessagingServiceSID)
	if msgSvc == "" {
		return nil, fmt.Errorf("twilio: twilio_messaging_service_sid not set")
	}
	return &TwilioSMSDispatcher{
		Users:               users,
		Journal:             journal,
		accountSID:          sid,
		authToken:           token,
		messagingServiceSID: msgSvc,
		http:                &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Dispatch resolves userID -> E.164 phone via the RecipientResolver
// and sends an SMS through Twilio. Returns nil when the user has no
// phone on file — the channel-level no-op signal documented on
// port.MessageDispatcher. Wraps non-2xx responses and transport
// failures as errors so the worker logs and skips marking the
// notification sent.
func (d *TwilioSMSDispatcher) Dispatch(ctx context.Context, userID int, _ string, body string, _ map[string]string) error {
	if d.Users == nil {
		return fmt.Errorf("twilio: Users not set")
	}
	to, err := d.Users.PhoneFor(userID)
	if err != nil {
		return fmt.Errorf("twilio: lookup user %d: %w", userID, err)
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return nil
	}
	if err := d.post(ctx, to, body); err != nil {
		return fmt.Errorf("twilio: user %d: %w", userID, err)
	}
	return nil
}

// Send delivers an SMS to an explicit recipient, skipping userID resolution —
// for recipients that aren't users (e.g. a business contact during claim
// verification). to may be E.164 or a national number; data["country"] is the
// ISO-3166 region used to normalize a national number (ignored once to starts
// with "+"). title is unused — SMS carries only a body. Empty to is a no-op.
func (d *TwilioSMSDispatcher) Send(ctx context.Context, to, _, body string, data map[string]string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return nil
	}
	e164, err := ToE164(to, data["country"])
	if err != nil {
		return fmt.Errorf("twilio: %w", err)
	}
	if err := d.post(ctx, e164, body); err != nil {
		return fmt.Errorf("twilio: %w", err)
	}
	return nil
}

// post performs the Twilio Messages API call to an E.164 recipient. Errors are
// recipient-free so callers add their own context (user id, or none) without
// leaking the phone number into logs.
func (d *TwilioSMSDispatcher) post(ctx context.Context, to, body string) error {
	form := url.Values{}
	form.Set("To", to)
	form.Set("Body", body)
	form.Set("MessagingServiceSid", d.messagingServiceSID)

	endpoint := fmt.Sprintf(twilioSendURL, d.accountSID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.SetBasicAuth(d.accountSID, d.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Drain the body before returning so the underlying connection
		// goes back to the keep-alive pool. The previous 1 KiB
		// LimitReader silently truncated drains for legitimate
		// Twilio success responses (the Message resource JSON
		// regularly exceeds 1 KiB), leaving the connection wedged
		// for http.Transport's idle timeout (v0.4.4 perf). On the
		// success path we trust the peer — only the error path
		// caps the read to bound an attacker- or peer-controlled
		// error message.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
}

func ToE164(phone, isoCountry string) (string, error) {
	phone = strings.TrimSpace(phone)
	if phone == "" {
		return "", fmt.Errorf("phone is empty")
	}
	region := strings.ToUpper(strings.TrimSpace(isoCountry))
	num, err := phonenumbers.Parse(phone, region)
	if err != nil {
		return "", fmt.Errorf("parse phone %q (region %q): %w", phone, region, err)
	}
	if !phonenumbers.IsValidNumber(num) {
		return "", fmt.Errorf("invalid phone number %q for region %q", phone, region)
	}
	return phonenumbers.Format(num, phonenumbers.E164), nil
}
