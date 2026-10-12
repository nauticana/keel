package telephony

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/clock"
)

const twilioSignatureHeader = "X-Twilio-Signature"

// Twilio reads Twilio's voice status callbacks and messaging webhooks. The
// signing secret is the account's auth token. Twilio's signature carries no
// timestamp, so a replayed delivery verifies: deduplicate on ExternalID.
type Twilio struct {
	clock clock.Clock
}

var _ Provider = (*Twilio)(nil)

// NewTwilio uses clk to time an event Twilio sends without a timestamp; a nil
// clk means the system clock.
func NewTwilio(clk clock.Clock) *Twilio { return &Twilio{clock: clk} }

func (p *Twilio) Name() string { return "twilio" }

// Ack is empty TwiML: Twilio reads a messaging webhook's reply as TwiML, and
// an empty response sends nothing back to the texter.
func (p *Twilio) Ack() (string, string) { return "text/xml", "<Response></Response>" }

func (p *Twilio) Events(webhook Webhook, authToken string) ([]Event, error) {
	signature := webhook.Header.Get(twilioSignatureHeader)
	if err := checkSize(webhook, signature); err != nil {
		return nil, err
	}
	if authToken == "" || signature == "" {
		return nil, fmt.Errorf("%w: missing twilio auth token or signature", ErrSignature)
	}
	form, err := url.ParseQuery(string(webhook.Body))
	if err != nil {
		return nil, fmt.Errorf("%w: twilio form: %v", ErrPayload, err)
	}
	if !hmac.Equal([]byte(twilioSignature(authToken, webhook.URL, form)), []byte(signature)) {
		return nil, ErrSignature
	}
	var event *Event
	if sid := form.Get("CallSid"); sid != "" {
		event, err = p.call(form, sid)
	} else if sid := cmp.Or(form.Get("MessageSid"), form.Get("SmsSid")); sid != "" {
		event = p.message(form, sid)
	} else {
		return nil, fmt.Errorf("%w: twilio request is neither a call nor a message", ErrPayload)
	}
	if err != nil || event == nil {
		return nil, err
	}
	if event.Counterpart() == "" {
		return nil, fmt.Errorf("%w: twilio %s without a number", ErrPayload, event.ExternalID)
	}
	return []Event{*event}, nil
}

// call reports only a final status; ringing and in-progress callbacks of the
// same call carry nothing that lasts.
func (p *Twilio) call(form url.Values, sid string) (*Event, error) {
	status := form.Get("CallStatus")
	switch status {
	case "completed", "busy", "no-answer", "failed", "canceled":
	default:
		return nil, nil
	}
	var seconds int
	if raw := form.Get("CallDuration"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w: twilio CallDuration %q", ErrPayload, raw)
		}
		seconds = n
	}
	at, err := p.timestamp(form.Get("Timestamp"))
	if err != nil {
		return nil, err
	}
	direction := DirectionInbound
	if strings.HasPrefix(form.Get("Direction"), "outbound") {
		direction = DirectionOutbound
	}
	answered := status == "completed"
	event := &Event{
		Kind: KindCall, Direction: direction, ExternalID: sid,
		From: form.Get("From"), To: form.Get("To"), At: at,
		Answered: answered, RecordingURL: form.Get("RecordingUrl"),
	}
	if seconds > 0 {
		event.Duration = time.Duration(seconds) * time.Second
	}
	return event, nil
}

// message reports a received message and a send's final outcome; queued,
// accepted and sending carry nothing that lasts.
func (p *Twilio) message(form url.Values, sid string) *Event {
	var status MessageStatus
	switch cmp.Or(form.Get("MessageStatus"), form.Get("SmsStatus")) {
	case "received":
		status = MessageReceived
	case "sent":
		status = MessageSent
	case "delivered":
		status = MessageDelivered
	case "undelivered", "failed":
		status = MessageFailed
	default:
		return nil
	}
	direction := DirectionOutbound
	if status == MessageReceived {
		direction = DirectionInbound
	}
	return &Event{
		Kind: KindMessage, Direction: direction, ExternalID: sid,
		From: form.Get("From"), To: form.Get("To"), At: p.now(), MessageStatus: status,
	}
}

func (p *Twilio) timestamp(raw string) (time.Time, error) {
	if raw == "" {
		return p.now(), nil
	}
	t, err := time.Parse(time.RFC1123Z, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: twilio Timestamp %q", ErrPayload, raw)
	}
	return t, nil
}

func (p *Twilio) now() time.Time {
	if p.clock == nil {
		return time.Now()
	}
	return p.clock.Now()
}

// twilioSignature is base64(HMAC-SHA1(token, url + each param name and value
// in name order)).
func twilioSignature(authToken, fullURL string, form url.Values) string {
	mac := hmac.New(sha1.New, []byte(authToken))
	mac.Write([]byte(fullURL))
	for _, name := range slices.Sorted(maps.Keys(form)) {
		values := slices.Clone(form[name])
		slices.Sort(values)
		for _, value := range slices.Compact(values) {
			mac.Write([]byte(name + value))
		}
	}
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
