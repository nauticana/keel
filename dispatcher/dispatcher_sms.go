package dispatcher

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
	"github.com/nyaruka/phonenumbers"
)

// smsHTTPTimeout bounds a single SMS provider API call.
const smsHTTPTimeout = 15 * time.Second

// smsDispatcher is the provider-agnostic SMS dispatch flow shared by every SMS
// provider. Providers supply postFn (the wire call to their API); the
// userID→phone resolution, E.164 normalization, and no-op-on-empty semantics
// are identical across providers and live here once.
type smsDispatcher struct {
	users   port.RecipientResolver
	journal logger.ApplicationLogger
	name    string // provider name, for error prefixes
	postFn  func(ctx context.Context, to, body string) error
}

var _ port.MessageDispatcher = (*smsDispatcher)(nil)

// Dispatch resolves userID -> E.164 phone via the RecipientResolver and sends.
// Returns nil when the user has no phone on file (the channel-level no-op
// documented on port.MessageDispatcher).
func (d *smsDispatcher) Dispatch(ctx context.Context, userID int, _ string, body string, _ map[string]string) error {
	if d.users == nil {
		return fmt.Errorf("%s: users not set", d.name)
	}
	to, err := d.users.PhoneFor(userID)
	if err != nil {
		return fmt.Errorf("%s: lookup user %d: %w", d.name, userID, err)
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return nil
	}
	if err := d.postFn(ctx, to, body); err != nil {
		return fmt.Errorf("%s: user %d: %w", d.name, userID, err)
	}
	return nil
}

// Send delivers to an explicit recipient, skipping userID resolution — for
// recipients that aren't users. to may be E.164 or national; data["country"]
// is the ISO-3166 region used to normalize a national number. Empty to = no-op.
func (d *smsDispatcher) Send(ctx context.Context, to, _, body string, data map[string]string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return nil
	}
	e164, err := ToE164(to, data["country"])
	if err != nil {
		return fmt.Errorf("%s: %w", d.name, err)
	}
	if err := d.postFn(ctx, e164, body); err != nil {
		return fmt.Errorf("%s: %w", d.name, err)
	}
	return nil
}

// NewSMSDispatcher builds the SMS dispatcher selected by config sms_provider
// (twilio | telnyx). Returns an error when the provider is unset/unknown or a
// required credential/id is missing, so callers register the "sms" channel
// only on success and cleanly run with SMS disabled otherwise.
func NewSMSDispatcher(ctx context.Context, secrets secret.SecretProvider, users port.RecipientResolver, journal logger.ApplicationLogger) (port.MessageDispatcher, error) {
	switch strings.ToLower(strings.TrimSpace(common.Config().SMSProvider)) {
	case "twilio":
		return newTwilioSMSDispatcher(ctx, secrets, users, journal)
	case "telnyx":
		return newTelnyxSMSDispatcher(ctx, secrets, users, journal)
	case "":
		return nil, fmt.Errorf("sms: sms_provider not set")
	default:
		return nil, fmt.Errorf("sms: unknown sms_provider %q", common.Config().SMSProvider)
	}
}

// smsHTTPClient is the shared per-provider HTTP client (dedicated, not the
// outbound client, so SMS keeps its own tight timeout). Redirects are not
// followed: a 3xx from a provider Messages endpoint is an error to surface, not
// a POST to silently replay against another host.
func smsHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       smsHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ToE164 normalizes a phone number to E.164 using isoCountry as the region hint
// for national-format input (ignored once the number starts with "+").
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
